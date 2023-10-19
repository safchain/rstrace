package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/safchain/rstrace/pkg/proto"
	"github.com/safchain/rstrace/pkg/rstrace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	fmt.Printf("Run %v\n", os.Args[1:])

	// GRPC
	conn, err := grpc.Dial("localhost:7878", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := proto.NewSyscallMsgStreamClient(conn)

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

	ctx := context.Background()

	containerCtx := proto.ContainerContext{
		ID:        os.Getenv("DD_CONTAINER_ID"),
		Name:      os.Getenv("DD_CONTAINER_NAME"),
		Tag:       os.Getenv("DD_CONTAINER_TAG"),
		CreatedAt: uint64(time.Now().UnixNano()),
	}

	tracer := rstrace.NewTracer(cmd.Process.Pid)

	ch := make(chan proto.SyscallMsg, 10000)
	go func() {
		msg := proto.SyscallMsg{
			ContainerContext: &containerCtx,
		}

		msg.Type = proto.SyscallType_Exec
		msg.PID = uint32(cmd.Process.Pid)
		msg.Exec = &proto.ExecSyscallMsg{
			Filename: os.Args[1],
			Args:     os.Args[1:],
			Envs:     os.Environ(),
		}

		_, err := client.SendSyscallMsg(ctx, &msg)
		if err != nil {
			for err != nil {
				_, err = client.SendSyscallMsg(ctx, &msg)
			}
		}

		for msg := range ch {
			fmt.Printf("SEND : %+v\n", msg)
			client.SendSyscallMsg(ctx, &msg)
		}
	}()

	cb := func(pid uint32, ppid uint32, regs syscall.PtraceRegs) {
		msg := proto.SyscallMsg{
			ContainerContext: &containerCtx,
		}

		name := tracer.GetSyscallName(regs)

		switch name {
		case "open":
			fmt.Printf("OPEN\n")
		case "openat2":
			fmt.Printf("OPEN2\n")
		case "openat":
			filename, _ := tracer.ReadArgString(regs, 1)
			msg.Type = proto.SyscallType_Open
			msg.PID = pid
			msg.Open = &proto.OpenSyscallMsg{
				Filename: filename,
				Flags:    uint32(tracer.ReadArgUint64(regs, 2)),
				Mode:     uint32(tracer.ReadArgUint64(regs, 3)),
			}
		case "fork", "vfork", "clone":
			msg.Type = proto.SyscallType_Fork
			msg.PID = pid
			msg.Fork = &proto.ForkSyscallMsg{
				PPID: ppid,
			}
		case "execve":
			filename, _ := tracer.ReadArgString(regs, 0)
			args, _ := tracer.ReadArgStringArray(regs, 1)
			envs, _ := tracer.ReadArgStringArray(regs, 2)

			msg.Type = proto.SyscallType_Exec
			msg.PID = pid
			msg.Exec = &proto.ExecSyscallMsg{
				Filename: filename,
				Args:     args,
				Envs:     envs,
			}
		default:
			return
		}

		ch <- msg
	}

	tracer.Trace(cb)
}
