package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/safchain/rstrace/pkg/rstrace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	fmt.Printf("Run %v\n", os.Args[1:])

	//var opts []grpc.DialOption
	conn, err := grpc.Dial("localhost:7878", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := rstrace.NewSyscallMsgStreamClient(conn)

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

	context := rstrace.ContainerContext{ID: os.Getenv("DD_CONTAINER_ID"), Name: os.Getenv("DD_CONTAINER_NAME"), Tag: os.Getenv("DD_CONTAINER_TAG")}

	tracer := rstrace.NewTracer(cmd.Process.Pid, os.Args[1], os.Args[1:], []string{}, &context)

	ch := make(chan rstrace.SyscallMsg, 100)
	go tracer.Trace(ch)

	for msg := range ch {
		fmt.Printf(">> :%+v\n", msg)
		client.SendSyscallMsg(ctx, &msg)
	}
}
