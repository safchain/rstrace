package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/safchain/rstrace/pkg/proto"
	"github.com/safchain/rstrace/pkg/rstrace"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	grpcAddr string
	logLevel string
)

type PidNr struct {
	Pid int
	Nr  int
}

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

func trace(args []string) {
	setLogLevel()

	log.Infof("Run %v [%s]\n", args, os.Getenv("DD_CONTAINER_ID"))

	var (
		client proto.SyscallMsgStreamClient
	)

	// GRPC
	if grpcAddr != "" {
		conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		client = proto.NewSyscallMsgStreamClient(conn)
	}

	containerCtx := proto.ContainerContext{
		ID:        os.Getenv("DD_CONTAINER_ID"),
		Name:      os.Getenv("DD_CONTAINER_NAME"),
		Tag:       os.Getenv("DD_CONTAINER_TAG"),
		CreatedAt: uint64(time.Now().UnixNano()),
	}

	ctx := context.Background()

	opts := rstrace.Opts{
		Syscalls: []string{
			"open",
			"openat",
			"fork",
			"vfork",
			"clone",
			"execve",
			"execveat",
			"exit",
		},
	}

	tracer, err := rstrace.NewTracer(args[0], args, opts)
	if err != nil {
		log.Fatal(err)
	}

	msgChan := make(chan *proto.SyscallMsg, 10000)
	traceChan := make(chan bool)

	cache, err := lru.New[PidNr, *proto.SyscallMsg](1024)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		if client != nil {
			msg := <-msgChan
			log.Debugf("sending message: %+v", msg)

			_, err := client.SendSyscallMsg(ctx, msg)
			if err != nil {
				var lastLog time.Time
				for err != nil {
					now := time.Now()
					if time.Now().Sub(lastLog) > time.Second {
						log.Errorf("waiting for the server: %+v", err)
						lastLog = now
					}

					time.Sleep(100 * time.Millisecond)
					_, err = client.SendSyscallMsg(ctx, msg)
				}
			}
		}

		traceChan <- true

		for msg := range msgChan {
			log.Debugf("sending message: %+v", msg)
			if client != nil {
				client.SendSyscallMsg(ctx, msg)
			}
		}
	}()

	send := func(msg *proto.SyscallMsg) {
		select {
		case msgChan <- msg:
		default:
			log.Error("unable to send message")
		}
	}

	cb := func(cbType rstrace.CallbackType, nr int, pid int, ppid int, regs syscall.PtraceRegs) {
		key := PidNr{
			Pid: pid,
			Nr:  nr,
		}

		switch cbType {
		case rstrace.CallbackPreType:
			msg := &proto.SyscallMsg{
				ContainerContext: &containerCtx,
			}
			cache.Add(key, msg)

			switch nr {
			case rstrace.OpenNr:
				if err := handleOpen(tracer, msg, pid, regs, 0); err != nil {
					log.Errorf("unable to handle open: %v", err)
					return
				}
			case rstrace.OpenatNr:
				if err := handleOpen(tracer, msg, pid, regs, 1); err != nil {
					log.Errorf("unable to handle openat: %v", err)
					return
				}
			case rstrace.ExecveNr:
				if err = handleExecve(tracer, msg, pid, regs, 0); err != nil {
					log.Errorf("unable to handle execve: %v", err)
					return
				}
			case rstrace.ExecveatNr:
				if err = handleExecve(tracer, msg, pid, regs, 1); err != nil {
					log.Errorf("unable to handle execveat: %v", err)
					return
				}
			}
		case rstrace.CallbackPostType:
			switch nr {
			case rstrace.ExecveNr, rstrace.ExecveatNr:
				msg, exists := cache.Get(key)
				if !exists {
					return
				}
				send(msg)
			case rstrace.OpenNr, rstrace.OpenatNr:
				if tracer.ReadRet(regs) >= 0 {
					msg, exists := cache.Get(key)
					if !exists {
						return
					}
					send(msg)
				}
			case rstrace.ForkNr, rstrace.VforkNr, rstrace.CloneNr:
				msg := &proto.SyscallMsg{
					ContainerContext: &containerCtx,
				}
				msg.Type = proto.SyscallType_Fork
				msg.PID = uint32(pid)
				msg.Fork = &proto.ForkSyscallMsg{
					PPID: uint32(ppid),
				}
				send(msg)
			}
		case rstrace.CallbackExitType:
			msg := &proto.SyscallMsg{
				ContainerContext: &containerCtx,
			}
			msg.Type = proto.SyscallType_Exit
			msg.PID = uint32(pid)
			send(msg)
		}
	}

	<-traceChan

	tracer.Trace(cb)
}

func setLogLevel() {
	switch logLevel {
	case "debug", "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "warn", "WARN":
		log.SetLevel(log.WarnLevel)
	case "error", "ERROR":
		log.SetLevel(log.ErrorLevel)
	case "trace", "TRACE":
		log.SetLevel(log.TraceLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

var rootCmd = &cobra.Command{
	Use:   "rstrace",
	Short: "rstrace - just another ptracer",
	Long:  `rstrace is just another ptracer`,
	Run: func(cmd *cobra.Command, args []string) {
		trace(args)
	},
}

func main() {
	rootCmd.Flags().StringVar(&grpcAddr, "grpc", "", "grpc address")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error while executing rstrace'%s'", err)
		os.Exit(1)
	}
}
