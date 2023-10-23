package rstrace

import (
	"encoding/binary"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	sec "github.com/seccomp/libseccomp-golang"
)

const (
	EventFork  = 1
	EventVFork = 2
	EventClone = 3
)

type Tracer struct {
	PID int
}

func waitEvent(status syscall.WaitStatus) uint32 {
	return (uint32(status) >> 16) & 0xff
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

func (t *Tracer) ReadRet(regs syscall.PtraceRegs) uint64 {
	return regs.Rax
}

func (t *Tracer) readString(pid int, ptr uint64) (string, error) {
	var (
		result []byte
		data   = make([]byte, 1)
		i      uint64
	)

	// TODO : process_vm_readv
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

func (t *Tracer) ReadArgString(pid int, regs syscall.PtraceRegs, arg int) (string, error) {
	ptr := t.argToRegValue(regs, arg)
	return t.readString(pid, ptr)
}

func (t *Tracer) GetSyscallName(regs syscall.PtraceRegs) string {
	name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
	return name
}

func (t *Tracer) ReadArgStringArray(pid int, regs syscall.PtraceRegs, arg int) ([]string, error) {
	ptr := t.argToRegValue(regs, arg)

	var (
		result []string
		data   = make([]byte, 8)
		i      uint64
	)

	// TODO : process_vm_readv
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

func (t *Tracer) Trace(cb func(pid int, ppid uint32, regs syscall.PtraceRegs)) error {
	var waitStatus syscall.WaitStatus

	if err := syscall.PtraceSyscall(t.PID, 0); err != nil {
		return err
	}

	for {
		pid, err := syscall.Wait4(-1, &waitStatus, 0, nil)
		if err != nil {
			break
		}

		if waitStatus.Exited() || waitStatus.Signaled() {
			if pid == t.PID {
				break
			}
			continue
		}

		var regs syscall.PtraceRegs

		if waitStatus.Stopped() {
			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				break
			}

			switch waitEvent(waitStatus) {
			case EventFork, EventVFork, EventClone:
				if npid, err := syscall.PtraceGetEventMsg(pid); err == nil {
					cb(int(npid), uint32(pid), regs)
				}
			default:
				if -regs.Rax == uint64(syscall.ENOSYS) {
					name := t.GetSyscallName(regs)

					switch name {
					case "fork", "vfork", "clone":
					default:
						cb(pid, 0, regs)
					}
				} else {
					// exit of syscall
				}
			}

			if err := syscall.PtraceSyscall(pid, 0); err != nil {
				continue
			}
		}
	}

	return nil
}

func NewTracer(name string, args ...string) *Tracer {
	runtime.LockOSThread()

	// INIT
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}
	cmd.Wait()

	const flags = syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEEXEC |
		syscall.PTRACE_O_TRACESYSGOOD

	syscall.PtraceSetOptions(cmd.Process.Pid, flags)

	return &Tracer{
		PID: cmd.Process.Pid,
	}
}
