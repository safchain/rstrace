// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.6.1
// source: pkg/rstrace/service.proto

package rstrace

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SyscallMsgStream_SendSyscallMsg_FullMethodName = "/rstrace.SyscallMsgStream/SendSyscallMsg"
)

// SyscallMsgStreamClient is the client API for SyscallMsgStream service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SyscallMsgStreamClient interface {
	SendSyscallMsg(ctx context.Context, in *SyscallMsg, opts ...grpc.CallOption) (*Response, error)
}

type syscallMsgStreamClient struct {
	cc grpc.ClientConnInterface
}

func NewSyscallMsgStreamClient(cc grpc.ClientConnInterface) SyscallMsgStreamClient {
	return &syscallMsgStreamClient{cc}
}

func (c *syscallMsgStreamClient) SendSyscallMsg(ctx context.Context, in *SyscallMsg, opts ...grpc.CallOption) (*Response, error) {
	out := new(Response)
	err := c.cc.Invoke(ctx, SyscallMsgStream_SendSyscallMsg_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SyscallMsgStreamServer is the server API for SyscallMsgStream service.
// All implementations must embed UnimplementedSyscallMsgStreamServer
// for forward compatibility
type SyscallMsgStreamServer interface {
	SendSyscallMsg(context.Context, *SyscallMsg) (*Response, error)
	mustEmbedUnimplementedSyscallMsgStreamServer()
}

// UnimplementedSyscallMsgStreamServer must be embedded to have forward compatible implementations.
type UnimplementedSyscallMsgStreamServer struct {
}

func (UnimplementedSyscallMsgStreamServer) SendSyscallMsg(context.Context, *SyscallMsg) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendSyscallMsg not implemented")
}
func (UnimplementedSyscallMsgStreamServer) mustEmbedUnimplementedSyscallMsgStreamServer() {}

// UnsafeSyscallMsgStreamServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SyscallMsgStreamServer will
// result in compilation errors.
type UnsafeSyscallMsgStreamServer interface {
	mustEmbedUnimplementedSyscallMsgStreamServer()
}

func RegisterSyscallMsgStreamServer(s grpc.ServiceRegistrar, srv SyscallMsgStreamServer) {
	s.RegisterService(&SyscallMsgStream_ServiceDesc, srv)
}

func _SyscallMsgStream_SendSyscallMsg_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SyscallMsg)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SyscallMsgStreamServer).SendSyscallMsg(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SyscallMsgStream_SendSyscallMsg_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SyscallMsgStreamServer).SendSyscallMsg(ctx, req.(*SyscallMsg))
	}
	return interceptor(ctx, in, info, handler)
}

// SyscallMsgStream_ServiceDesc is the grpc.ServiceDesc for SyscallMsgStream service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SyscallMsgStream_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "rstrace.SyscallMsgStream",
	HandlerType: (*SyscallMsgStreamServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendSyscallMsg",
			Handler:    _SyscallMsgStream_SendSyscallMsg_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/rstrace/service.proto",
}
