package main

import (
	"context"
	"os"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/safchain/rstrace/pkg/proto"
	"github.com/safchain/rstrace/pkg/rstrace"
)

func handleOpen(tracer *rstrace.Tracer, msg *proto.SyscallMsg, pid int, regs syscall.PtraceRegs, firstReg int) error {
	filename, err := tracer.ReadArgString(pid, regs, firstReg)
	if err != nil {
		return err
	}
	msg.Type = proto.SyscallType_Open
	msg.PID = uint32(pid)
	msg.Open = &proto.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(tracer.ReadArgUint64(regs, firstReg+1)),
		Mode:     uint32(tracer.ReadArgUint64(regs, firstReg+2)),
	}

	return nil
}

func handleExecve(tracer *rstrace.Tracer, msg *proto.SyscallMsg, pid int, regs syscall.PtraceRegs, firstReg int) error {
	filename, err := tracer.ReadArgString(pid, regs, firstReg)
	if err != nil {
		return err
	}
	args, err := tracer.ReadArgStringArray(pid, regs, firstReg+1)
	if err != nil {
		return err
	}
	envs, err := tracer.ReadArgStringArray(pid, regs, firstReg+2)
	if err != nil {
		return err
	}

	msg.Type = proto.SyscallType_Exec
	msg.PID = uint32(pid)
	msg.Exec = &proto.ExecSyscallMsg{
		Filename: filename,
		Args:     args,
		Envs:     envs,
	}

	return nil
}

func main() {
	log.SetLevel(log.DebugLevel)

	log.Infof("Run %v [%s]\n", os.Args[1:], os.Getenv("DD_CONTAINER_ID"))

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

	tracer, err := rstrace.NewTracer(os.Args[1], os.Args[2:]...)
	if err != nil {
		panic(err)
	}

	msgChan := make(chan proto.SyscallMsg, 10000)
	traceChan := make(chan bool)

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
			var lastLog time.Time
			for err != nil {
				now := time.Now()
				if time.Now().Sub(lastLog) > time.Second {
					log.Errorf("waiting for the server: %+v", err)
					lastLog = now
				}

				time.Sleep(100 * time.Millisecond)
				_, err = client.SendSyscallMsg(ctx, &msg)
			}
		}

		traceChan <- true

		for msg := range msgChan {
			log.Debugf("send message: %+v", msg)
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
			if err := handleOpen(tracer, &msg, pid, regs, 0); err != nil {
				log.Errorf("unable to handle open: %v", err)
				return
			}
		case "openat":
			if err := handleOpen(tracer, &msg, pid, regs, 1); err != nil {
				log.Errorf("unable to handle openat: %v", err)
				return
			}
		case "fork", "vfork", "clone":
			msg.Type = proto.SyscallType_Fork
			msg.PID = uint32(pid)
			msg.Fork = &proto.ForkSyscallMsg{
				PPID: ppid,
			}
		case "execve":
			if err = handleExecve(tracer, &msg, pid, regs, 0); err != nil {
				log.Errorf("unable to handle execve: %v", err)
				return
			}
		case "execveat":
			if err = handleExecve(tracer, &msg, pid, regs, 1); err != nil {
				log.Errorf("unable to handle execveat: %v", err)
				return
			}
		default:
			return
		}

		msgChan <- msg
	}

	<-traceChan

	tracer.Trace(cb)
}
