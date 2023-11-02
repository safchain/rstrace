package rstrace

type SyscallNr = int

const (
	// syscall Nrs
	OpenNr     SyscallNr = 2
	OpenatNr   SyscallNr = 257
	ExecveNr   SyscallNr = 59
	ExecveatNr SyscallNr = 322
	CloneNr    SyscallNr = 56
	ForkNr     SyscallNr = 57
	VforkNr    SyscallNr = 58
	ExitNr     SyscallNr = 60
	FcntlNr    SyscallNr = 72
)
