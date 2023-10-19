package rstrace

import (
	"encoding/binary"
	"runtime"
	"syscall"

	sec "github.com/seccomp/libseccomp-golang"
)

const (
	EventFork  = 1
	EventVFork = 2
	EventClone = 3
)

const (
	ExecSyscallType = iota + 1
	ForkSyscallType
	OpenSyscallType
)

type Tracer struct {
	PID              int
	Filename         string
	Args             []string
	Envs             []string
	ContainerContext *ContainerContext
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

func (t *Tracer) readString(ptr uint64) (string, error) {
	var (
		result []byte
		data   = make([]byte, 1)
		i      uint64
	)

	for {
		n, err := syscall.PtracePeekData(t.PID, uintptr(ptr+i), data)
		if err != nil || n != len(data) {
			return "", err
		}
		result = append(result, data[0])

		if data[0] == 0 {
			break
		}

		i += uint64(len(data))
	}

	return string(result), nil
}

func (t *Tracer) ReadArgString(regs syscall.PtraceRegs, arg int) (string, error) {
	ptr := t.argToRegValue(regs, arg)
	return t.readString(ptr)
}

func (t *Tracer) GetSyscallName(regs syscall.PtraceRegs) string {
	name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
	return name
}

func (t *Tracer) ReadArgStringArray(regs syscall.PtraceRegs, arg int) ([]string, error) {
	ptr := t.argToRegValue(regs, arg)

	var (
		result []string
		data   = make([]byte, 8)
		i      uint64
	)

	for {
		n, err := syscall.PtracePeekData(t.PID, uintptr(ptr+i), data)
		if err != nil || n != len(data) {
			return result, err
		}

		ptr := binary.LittleEndian.Uint64(data)
		if ptr == 0 {
			break
		}

		str, err := t.readString(ptr)
		if err != nil {
			break
		}
		result = append(result, str)

		i += uint64(len(data))
	}

	return result, nil
}

func (t *Tracer) Trace(syscalls chan SyscallMsg) error {
	var ts SyscallMsg

	// send the first exec
	ts.Type = ExecSyscallType
	ts.PID = uint32(t.PID)
	ts.Exec = &ExecSyscallMsg{
		Filename: t.Filename,
		Args:     t.Args,
		Envs:     t.Envs,
	}
	syscalls <- ts

	runtime.LockOSThread()

	var waitStatus syscall.WaitStatus

	if err := syscall.PtraceSyscall(t.PID, 0); err != nil {
		return err
	}

	for {
		ts = SyscallMsg{}

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

		if waitStatus.Stopped() {
			switch waitEvent(waitStatus) {
			case EventFork, EventVFork, EventClone:
				if npid, err := syscall.PtraceGetEventMsg(pid); err == nil {
					ts.PID = uint32(npid)
					ts.Type = ForkSyscallType
					ts.Fork = &ForkSyscallMsg{
						PPID: uint32(pid),
					}

					syscalls <- ts
				}
			default:
				var regs syscall.PtraceRegs
				if err := syscall.PtraceGetRegs(pid, &regs); err == nil {
					if -regs.Rax == uint64(syscall.ENOSYS) {
						ts.PID = uint32(pid)

						name := t.GetSyscallName(regs)
						switch name {
						case "openat":
							filename, _ := t.ReadArgString(regs, 1)
							ts.Type = OpenSyscallType
							ts.Open = &OpenSyscallMsg{
								Filename: filename,
								Flags:    uint32(t.argToRegValue(regs, 2)),
								Mode:     uint32(t.argToRegValue(regs, 3)),
							}

							syscalls <- ts
						case "execve":
							filename, _ := t.ReadArgString(regs, 0)
							args, _ := t.ReadArgStringArray(regs, 1)
							envs, _ := t.ReadArgStringArray(regs, 2)

							ts.Type = ExecSyscallType
							ts.Exec = &ExecSyscallMsg{
								Filename: filename,
								Args:     args,
								Envs:     envs,
							}

							syscalls <- ts
						}
					} else {
						// exit of syscall
					}
				}
			}

			if err := syscall.PtraceSyscall(pid, 0); err != nil {
				continue
			}
		}
	}

	close(syscalls)

	return nil
}

func NewTracer(pid int, filename string, args []string, envs []string, context *ContainerContext) *Tracer {
	const flags = syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEEXEC |
		syscall.PTRACE_O_TRACESYSGOOD

	syscall.PtraceSetOptions(pid, flags)

	return &Tracer{
		PID:              pid,
		Filename:         filename,
		Args:             args,
		Envs:             envs,
		ContainerContext: context,
	}
}
