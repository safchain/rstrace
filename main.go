package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/safchain/rstrace/pkg/proto"
	"github.com/safchain/rstrace/pkg/rstrace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	fmt.Printf("Run %v [%s]\n", os.Args[1:], os.Getenv("DD_CONTAINER_ID"))

	// GRPC
	conn, err := grpc.Dial("localhost:7878", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := proto.NewSyscallMsgStreamClient(conn)

	containerCtx := proto.ContainerContext{
		ID:        os.Getenv("DD_CONTAINER_ID"),
		Name:      os.Getenv("DD_CONTAINER_NAME"),
		Tag:       os.Getenv("DD_CONTAINER_TAG"),
		CreatedAt: uint64(time.Now().UnixNano()),
	}

	ctx := context.Background()

	tracer := rstrace.NewTracer(os.Args[1], os.Args[2:]...)

	ch := make(chan proto.SyscallMsg, 10000)

	go func() {
		msg := proto.SyscallMsg{
			ContainerContext: &containerCtx,
		}

		msg.Type = proto.SyscallType_Exec
		msg.PID = uint32(tracer.PID)
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
			client.SendSyscallMsg(ctx, &msg)
		}
	}()

	cb := func(pid int, ppid uint32, regs syscall.PtraceRegs) {
		msg := proto.SyscallMsg{
			ContainerContext: &containerCtx,
		}

		name := tracer.GetSyscallName(regs)

		switch name {
		case "open":
			filename, err := tracer.ReadArgString(pid, regs, 0)
			if err != nil {
				return
			}
			msg.Type = proto.SyscallType_Open
			msg.PID = uint32(pid)
			msg.Open = &proto.OpenSyscallMsg{
				Filename: filename,
				Flags:    uint32(tracer.ReadArgUint64(regs, 1)),
				Mode:     uint32(tracer.ReadArgUint64(regs, 2)),
			}
		case "openat":
			filename, err := tracer.ReadArgString(pid, regs, 1)
			if err != nil {
				return
			}
			msg.Type = proto.SyscallType_Open
			msg.PID = uint32(pid)
			msg.Open = &proto.OpenSyscallMsg{
				Filename: filename,
				Flags:    uint32(tracer.ReadArgUint64(regs, 2)),
				Mode:     uint32(tracer.ReadArgUint64(regs, 3)),
			}
		case "fork", "vfork", "clone":
			msg.Type = proto.SyscallType_Fork
			msg.PID = uint32(pid)
			msg.Fork = &proto.ForkSyscallMsg{
				PPID: ppid,
			}
		case "execve":
			filename, err := tracer.ReadArgString(pid, regs, 0)
			if err != nil {
				return
			}
			args, err := tracer.ReadArgStringArray(pid, regs, 1)
			if err != nil {
				return
			}
			envs, err := tracer.ReadArgStringArray(pid, regs, 2)
			if err != nil {
				return
			}

			msg.Type = proto.SyscallType_Exec
			msg.PID = uint32(pid)
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
