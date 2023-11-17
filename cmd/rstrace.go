package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/safchain/rstrace/pkg/proto"
	"github.com/safchain/rstrace/pkg/rstrace"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	grpcAddr string
	logLevel string
)

type Process struct {
	Pid int
	Nr  map[int]*proto.SyscallMsg
	Fd  map[int32]string
}

func handleOpenAt(tracer *rstrace.Tracer, process *Process, msg *proto.SyscallMsg, regs syscall.PtraceRegs) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	if fd != unix.AT_FDCWD {
		if path, exists := process.Fd[fd]; exists {
			filename = filepath.Join(path, filename)
		}
	}

	msg.Type = proto.SyscallType_Open
	msg.Open = &proto.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(tracer.ReadArgUint64(regs, 2)),
		Mode:     uint32(tracer.ReadArgUint64(regs, 3)),
	}

	return nil
}

func handleOpen(tracer *rstrace.Tracer, process *Process, msg *proto.SyscallMsg, regs syscall.PtraceRegs) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	msg.Type = proto.SyscallType_Open
	msg.Open = &proto.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(tracer.ReadArgUint64(regs, 1)),
		Mode:     uint32(tracer.ReadArgUint64(regs, 2)),
	}

	return nil
}

func handleExecveAt(tracer *rstrace.Tracer, process *Process, msg *proto.SyscallMsg, regs syscall.PtraceRegs) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	if fd != unix.AT_FDCWD {
		if path, exists := process.Fd[fd]; exists {
			filename = filepath.Join(path, filename)
		}
	}

	args, err := tracer.ReadArgStringArray(process.Pid, regs, 2)
	if err != nil {
		return err
	}

	envs, err := tracer.ReadArgStringArray(process.Pid, regs, 3)
	if err != nil {
		return err
	}

	msg.Type = proto.SyscallType_Exec
	msg.Exec = &proto.ExecSyscallMsg{
		Filename: filename,
		Args:     args,
		Envs:     envs,
	}

	return nil
}

func handleFcntl(tracer *rstrace.Tracer, process *Process, msg *proto.SyscallMsg, regs syscall.PtraceRegs) error {
	msg.Type = proto.SyscallType_Fcntl
	msg.Fcntl = &proto.FcntlSyscallMsg{
		Fd:  tracer.ReadArgUint32(regs, 0),
		Cmd: tracer.ReadArgUint32(regs, 1),
	}
	return nil
}

func handleExecve(tracer *rstrace.Tracer, process *Process, msg *proto.SyscallMsg, regs syscall.PtraceRegs) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	args, err := tracer.ReadArgStringArray(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	envs, err := tracer.ReadArgStringArray(process.Pid, regs, 2)
	if err != nil {
		return err
	}

	msg.Type = proto.SyscallType_Exec
	msg.Exec = &proto.ExecSyscallMsg{
		Filename: filename,
		Args:     args,
		Envs:     envs,
	}

	return nil
}

type ECSMetadata struct {
	DockerID   string `json:"DockerId"`
	DockerName string `json:"DockerName"`
	Name       string `json:"Name"`
}

func retrieveECSMetadata(ctx *proto.ContainerContext) error {
	url := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if url == "" {
		return nil
	}
	client := http.Client{}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	data := ECSMetadata{}
	if err = json.Unmarshal(body, &data); err != nil {
		return err
	}

	if data.DockerID != "" {
		ctx.ID = data.DockerID
	}
	if data.DockerName != "" {
		ctx.Name = data.DockerName
	}

	return nil
}

func retrieveEnvMetadata(ctx *proto.ContainerContext) {
	if id := os.Getenv("DD_CONTAINER_ID"); id != "" {
		ctx.ID = id
	}

	if name := os.Getenv("DD_CONTAINER_NAME"); name != "" {
		ctx.Name = name
	}
}

func checkEntryPoint(path string) (string, error) {
	name, err := exec.LookPath(path)
	if err != nil {
		return "", err
	}

	name, err = filepath.Abs(name)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(name)
	if err != nil {
		return "", err
	}

	if !info.Mode().IsRegular() {
		return "", errors.New("entrypoint not a regular file")
	}

	if info.Mode()&0111 == 0 {
		return "", errors.New("entrypoint not an executable")
	}

	return name, nil
}

func trace(args []string) {
	setLogLevel()

	entry, err := checkEntryPoint(args[0])
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Run %s %v [%s]\n", entry, args, os.Getenv("DD_CONTAINER_ID"))

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

	var containerCtx proto.ContainerContext

	if err := retrieveECSMetadata(&containerCtx); err != nil {
		log.Fatal(err)
	}

	retrieveEnvMetadata(&containerCtx)

	containerCtx.CreatedAt = uint64(time.Now().UnixNano())

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
			"fcntl",
		},
	}

	tracer, err := rstrace.NewTracer(entry, args, opts)
	if err != nil {
		log.Fatal(err)
	}

	msgChan := make(chan *proto.SyscallMsg, 10000)
	traceChan := make(chan bool)

	cache, err := lru.New[int, *Process](1024)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		var seq uint64

		if client != nil {
			msg := &proto.SyscallMsg{}
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
			seq++
		}

		traceChan <- true

		for msg := range msgChan {
			msg.SeqNum = seq

			log.Debugf("sending message: %+v", msg)
			if client != nil {
				client.SendSyscallMsg(ctx, msg)
			}
			seq++
		}
	}()

	send := func(msg *proto.SyscallMsg) {
		if msg == nil {
			return
		}

		select {
		case msgChan <- msg:
		default:
			log.Error("unable to send message")
		}
	}

	cb := func(cbType rstrace.CallbackType, nr int, pid int, ppid int, regs syscall.PtraceRegs) {
		process, exists := cache.Get(pid)
		if !exists {
			process = &Process{
				Pid: pid,
				Nr:  make(map[int]*proto.SyscallMsg),
				Fd:  make(map[int32]string),
			}

			cache.Add(pid, process)
		}

		switch cbType {
		case rstrace.CallbackPreType:
			msg := &proto.SyscallMsg{
				PID:              uint32(pid),
				ContainerContext: &containerCtx,
			}
			process.Nr[nr] = msg

			switch nr {
			case rstrace.OpenNr:
				if err := handleOpen(tracer, process, msg, regs); err != nil {
					log.Errorf("unable to handle open: %v", err)
					return
				}
			case rstrace.OpenatNr:
				if err := handleOpenAt(tracer, process, msg, regs); err != nil {
					log.Errorf("unable to handle openat: %v", err)
					return
				}
			case rstrace.ExecveNr:
				if err = handleExecve(tracer, process, msg, regs); err != nil {
					log.Errorf("unable to handle execve: %v", err)
					return
				}
			case rstrace.ExecveatNr:
				if err = handleExecveAt(tracer, process, msg, regs); err != nil {
					log.Errorf("unable to handle execveat: %v", err)
					return
				}
			case rstrace.FcntlNr:
				_ = handleFcntl(tracer, process, msg, regs)

			}
		case rstrace.CallbackPostType:
			switch nr {
			case rstrace.ExecveNr, rstrace.ExecveatNr:
				send(process.Nr[nr])
			case rstrace.OpenNr, rstrace.OpenatNr:
				if ret := tracer.ReadRet(regs); ret >= 0 {
					msg, exists := process.Nr[nr]
					if !exists {
						return
					}

					send(process.Nr[nr])

					// maintain fd/path mapping
					process.Fd[int32(ret)] = msg.Open.Filename
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
			case rstrace.FcntlNr:
				if ret := tracer.ReadRet(regs); ret >= 0 {
					msg, exists := process.Nr[nr]
					if !exists {
						return
					}

					// maintain fd/path mapping
					if msg.Fcntl.Cmd == unix.F_DUPFD || msg.Fcntl.Cmd == unix.F_DUPFD_CLOEXEC {
						if path, exists := process.Fd[int32(msg.Fcntl.Fd)]; exists {
							process.Fd[int32(ret)] = path
						}
					}
				}
				// TODO case dup, dup2, dup3, chdir
			}
		case rstrace.CallbackExitType:
			msg := &proto.SyscallMsg{
				ContainerContext: &containerCtx,
			}
			msg.Type = proto.SyscallType_Exit
			msg.PID = uint32(pid)
			send(msg)

			cache.Remove(pid)
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
	rootCmd.Flags().StringVar(&grpcAddr, "grpc", "localhost:5678", "grpc address")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error while executing rstrace'%s'", err)
		os.Exit(1)
	}
}
