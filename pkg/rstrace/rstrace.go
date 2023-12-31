package rstrace

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"syscall"

	"github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type CallbackType = int

const (
	CallbackPreType CallbackType = iota
	CallbackPostType
	CallbackExitType

	MaxStringSize = 4096
	Nsig          = 32
)

type Tracer struct {
	PID int

	// internals
	info *arch.Info
}

type Opts struct {
	Syscalls []string
}

// https://github.com/torvalds/linux/blob/v5.0/arch/x86/entry/entry_64.S#L126
func (t *Tracer) argToRegValue(regs syscall.PtraceRegs, arg int) uint64 {
	switch arg {
	case 0:
		return regs.Rdi
	case 1:
		return regs.Rsi
	case 2:
		return regs.Rdx
	case 3:
		return regs.R10
	case 4:
		return regs.R8
	case 5:
		return regs.R9
	}

	return 0
}

func (t *Tracer) ReadRet(regs syscall.PtraceRegs) int64 {
	return int64(regs.Rax)
}

func processVMReadv(pid int, addr uintptr, data []byte) (int, error) {
	size := len(data)

	localIov := []unix.Iovec{
		{Base: &data[0], Len: uint64(size)},
	}

	remoteIov := []unix.RemoteIovec{
		{Base: uintptr(addr), Len: size},
	}

	return unix.ProcessVMReadv(pid, localIov, remoteIov, 0)
}

func (t *Tracer) readString(pid int, ptr uint64) (string, error) {
	data := make([]byte, MaxStringSize)

	_, err := processVMReadv(pid, uintptr(ptr), data)
	if err != nil {
		return "", err
	}

	n := bytes.Index(data[:], []byte{0})
	if n < 0 {
		return "", nil
	}
	return string(data[:n]), nil
}

func (t *Tracer) PeekString(pid int, ptr uint64) (string, error) {
	var (
		result []byte
		data   = make([]byte, 1)
		i      uint64
	)

	for {
		n, err := syscall.PtracePeekData(pid, uintptr(ptr+i), data)
		if err != nil || n != len(data) {
			return "", err
		}
		if data[0] == 0 {
			break
		}

		result = append(result, data[0])

		i += uint64(len(data))
	}

	return string(result), nil
}

func (t *Tracer) ReadArgUint64(regs syscall.PtraceRegs, arg int) uint64 {
	return t.argToRegValue(regs, arg)
}

func (t *Tracer) ReadArgInt64(regs syscall.PtraceRegs, arg int) int64 {
	return int64(t.argToRegValue(regs, arg))
}

func (t *Tracer) ReadArgInt32(regs syscall.PtraceRegs, arg int) int32 {
	return int32(t.argToRegValue(regs, arg))
}

func (t *Tracer) ReadArgUint32(regs syscall.PtraceRegs, arg int) uint32 {
	return uint32(t.argToRegValue(regs, arg))
}

func (t *Tracer) ReadArgString(pid int, regs syscall.PtraceRegs, arg int) (string, error) {
	ptr := t.argToRegValue(regs, arg)
	return t.readString(pid, ptr)
}

func GetSyscallNr(regs syscall.PtraceRegs) int {
	return int(regs.Orig_rax)
}

func (t *Tracer) GetSyscallName(regs syscall.PtraceRegs) string {
	return t.info.SyscallNumbers[GetSyscallNr(regs)]
}

func (t *Tracer) ReadArgStringArray(pid int, regs syscall.PtraceRegs, arg int) ([]string, error) {
	ptr := t.argToRegValue(regs, arg)

	var (
		result []string
		data   = make([]byte, 8)
		i      uint64
	)

	for {
		n, err := syscall.PtracePeekData(pid, uintptr(ptr+i), data)
		if err != nil || n != len(data) {
			return result, err
		}

		ptr := binary.LittleEndian.Uint64(data)
		if ptr == 0 {
			break
		}

		str, err := t.readString(pid, ptr)
		if err != nil {
			break
		}
		result = append(result, str)

		i += uint64(len(data))
	}

	return result, nil
}

func (t *Tracer) Trace(cb func(cbType CallbackType, nr int, pid int, ppid int, regs syscall.PtraceRegs)) error {
	var waitStatus syscall.WaitStatus

	if err := syscall.PtraceCont(t.PID, 0); err != nil {
		return err
	}

	var regs syscall.PtraceRegs

	for {
		pid, err := syscall.Wait4(-1, &waitStatus, 0, nil)
		if err != nil {
			break
		}

		if waitStatus.Exited() || waitStatus.Signaled() {
			if pid == t.PID {
				break
			}
			cb(CallbackExitType, ExitNr, pid, 0, regs)
			continue
		}

		if waitStatus.Stopped() {
			if signal := waitStatus.StopSignal(); signal != syscall.SIGTRAP {
				if signal < Nsig {
					_ = syscall.PtraceCont(pid, int(signal))

				} else {
					_ = syscall.PtraceCont(pid, 0)
				}
				continue
			}

			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				break
			}

			nr := GetSyscallNr(regs)

			switch waitStatus.TrapCause() {
			case syscall.PTRACE_EVENT_CLONE, syscall.PTRACE_EVENT_FORK, syscall.PTRACE_EVENT_VFORK:
				if npid, err := syscall.PtraceGetEventMsg(pid); err == nil {
					cb(CallbackPostType, nr, int(npid), int(pid), regs)
				}
			case unix.PTRACE_EVENT_SECCOMP:
				switch nr {
				case ForkNr, VforkNr, CloneNr:
					// already handled
				default:
					cb(CallbackPreType, nr, pid, 0, regs)

					// force a ptrace syscall in order to get to return value
					if err := syscall.PtraceSyscall(pid, 0); err != nil {
						continue
					}
				}
			default:
				switch nr {
				case ForkNr, VforkNr, CloneNr:
					// already handled
				case ExecveNr, ExecveatNr:
					// does not return on success, thus ret value stay at syscall.ENOSYS
					if ret := -t.ReadRet(regs); ret == int64(syscall.ENOSYS) {
						cb(CallbackPostType, nr, pid, 0, regs)
					}
				default:
					if ret := -t.ReadRet(regs); ret != int64(syscall.ENOSYS) {
						cb(CallbackPostType, nr, pid, 0, regs)
					}
				}
			}

			if err := syscall.PtraceCont(pid, 0); err != nil {
				continue
			}
		}
	}

	return nil
}
func traceFilterProg(opts Opts) (*syscall.SockFprog, error) {
	policy := seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{
				Action: seccomp.ActionTrace,
				Names:  opts.Syscalls,
			},
		},
	}

	insts, err := policy.Assemble()
	if err != nil {
		return nil, err
	}
	rawInsts, err := bpf.Assemble(insts)
	if err != nil {
		return nil, err
	}

	filter := make([]syscall.SockFilter, 0, len(rawInsts))
	for _, instruction := range rawInsts {
		filter = append(filter, syscall.SockFilter{
			Code: instruction.Op,
			Jt:   instruction.Jt,
			Jf:   instruction.Jf,
			K:    instruction.K,
		})
	}
	return &syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}, nil
}

func NewTracer(path string, args []string, opts Opts) (*Tracer, error) {
	info, err := arch.GetInfo("")
	if err != nil {
		return nil, err
	}

	prog, err := traceFilterProg(opts)
	if err != nil {
		return nil, err
	}

	runtime.LockOSThread()

	pid, err := forkExec(path, args, os.Environ(), prog)
	if err != nil {
		return nil, err
	}

	var wstatus syscall.WaitStatus
	if _, err = syscall.Wait4(pid, &wstatus, 0, nil); err != nil {
		return nil, err
	}

	const flags = 0 |
		syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEEXEC |
		syscall.PTRACE_O_TRACESYSGOOD |
		unix.PTRACE_O_TRACESECCOMP

	syscall.PtraceSetOptions(pid, flags)

	return &Tracer{
		PID:  pid,
		info: info,
	}, nil
}
