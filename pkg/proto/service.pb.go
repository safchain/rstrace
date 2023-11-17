// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
//  protoc
// source: pkg/security/proto/ebpfless/service.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SyscallType int32

const (
	SyscallType_Unknown SyscallType = 0
	SyscallType_Exec    SyscallType = 1
	SyscallType_Fork    SyscallType = 2
	SyscallType_Open    SyscallType = 3
	SyscallType_Exit    SyscallType = 4
	SyscallType_Fcntl   SyscallType = 5
)

// Enum value maps for SyscallType.
var (
	SyscallType_name = map[int32]string{
		0: "Unknown",
		1: "Exec",
		2: "Fork",
		3: "Open",
		4: "Exit",
		5: "Fcntl",
	}
	SyscallType_value = map[string]int32{
		"Unknown": 0,
		"Exec":    1,
		"Fork":    2,
		"Open":    3,
		"Exit":    4,
		"Fcntl":   5,
	}
)

func (x SyscallType) Enum() *SyscallType {
	p := new(SyscallType)
	*p = x
	return p
}

func (x SyscallType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SyscallType) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_security_proto_ebpfless_service_proto_enumTypes[0].Descriptor()
}

func (SyscallType) Type() protoreflect.EnumType {
	return &file_pkg_security_proto_ebpfless_service_proto_enumTypes[0]
}

func (x SyscallType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SyscallType.Descriptor instead.
func (SyscallType) EnumDescriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{0}
}

type ContainerContext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ID        string `protobuf:"bytes,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Name      string `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	Tag       string `protobuf:"bytes,3,opt,name=Tag,proto3" json:"Tag,omitempty"`
	CreatedAt uint64 `protobuf:"varint,4,opt,name=CreatedAt,proto3" json:"CreatedAt,omitempty"`
}

func (x *ContainerContext) Reset() {
	*x = ContainerContext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ContainerContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerContext) ProtoMessage() {}

func (x *ContainerContext) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerContext.ProtoReflect.Descriptor instead.
func (*ContainerContext) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{0}
}

func (x *ContainerContext) GetID() string {
	if x != nil {
		return x.ID
	}
	return ""
}

func (x *ContainerContext) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ContainerContext) GetTag() string {
	if x != nil {
		return x.Tag
	}
	return ""
}

func (x *ContainerContext) GetCreatedAt() uint64 {
	if x != nil {
		return x.CreatedAt
	}
	return 0
}

type FcntlSyscallMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Fd  uint32 `protobuf:"varint,1,opt,name=Fd,proto3" json:"Fd,omitempty"`
	Cmd uint32 `protobuf:"varint,2,opt,name=Cmd,proto3" json:"Cmd,omitempty"`
}

func (x *FcntlSyscallMsg) Reset() {
	*x = FcntlSyscallMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FcntlSyscallMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FcntlSyscallMsg) ProtoMessage() {}

func (x *FcntlSyscallMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FcntlSyscallMsg.ProtoReflect.Descriptor instead.
func (*FcntlSyscallMsg) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{1}
}

func (x *FcntlSyscallMsg) GetFd() uint32 {
	if x != nil {
		return x.Fd
	}
	return 0
}

func (x *FcntlSyscallMsg) GetCmd() uint32 {
	if x != nil {
		return x.Cmd
	}
	return 0
}

type ExecSyscallMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filename string   `protobuf:"bytes,1,opt,name=Filename,proto3" json:"Filename,omitempty"`
	Args     []string `protobuf:"bytes,2,rep,name=Args,proto3" json:"Args,omitempty"`
	Envs     []string `protobuf:"bytes,3,rep,name=Envs,proto3" json:"Envs,omitempty"`
}

func (x *ExecSyscallMsg) Reset() {
	*x = ExecSyscallMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExecSyscallMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExecSyscallMsg) ProtoMessage() {}

func (x *ExecSyscallMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExecSyscallMsg.ProtoReflect.Descriptor instead.
func (*ExecSyscallMsg) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{2}
}

func (x *ExecSyscallMsg) GetFilename() string {
	if x != nil {
		return x.Filename
	}
	return ""
}

func (x *ExecSyscallMsg) GetArgs() []string {
	if x != nil {
		return x.Args
	}
	return nil
}

func (x *ExecSyscallMsg) GetEnvs() []string {
	if x != nil {
		return x.Envs
	}
	return nil
}

type ForkSyscallMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PPID uint32 `protobuf:"varint,1,opt,name=PPID,proto3" json:"PPID,omitempty"`
}

func (x *ForkSyscallMsg) Reset() {
	*x = ForkSyscallMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ForkSyscallMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ForkSyscallMsg) ProtoMessage() {}

func (x *ForkSyscallMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ForkSyscallMsg.ProtoReflect.Descriptor instead.
func (*ForkSyscallMsg) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{3}
}

func (x *ForkSyscallMsg) GetPPID() uint32 {
	if x != nil {
		return x.PPID
	}
	return 0
}

type ExitSyscallMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ExitSyscallMsg) Reset() {
	*x = ExitSyscallMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExitSyscallMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExitSyscallMsg) ProtoMessage() {}

func (x *ExitSyscallMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExitSyscallMsg.ProtoReflect.Descriptor instead.
func (*ExitSyscallMsg) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{4}
}

type OpenSyscallMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filename string `protobuf:"bytes,1,opt,name=Filename,proto3" json:"Filename,omitempty"`
	Flags    uint32 `protobuf:"varint,2,opt,name=Flags,proto3" json:"Flags,omitempty"`
	Mode     uint32 `protobuf:"varint,3,opt,name=Mode,proto3" json:"Mode,omitempty"`
}

func (x *OpenSyscallMsg) Reset() {
	*x = OpenSyscallMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OpenSyscallMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OpenSyscallMsg) ProtoMessage() {}

func (x *OpenSyscallMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OpenSyscallMsg.ProtoReflect.Descriptor instead.
func (*OpenSyscallMsg) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{5}
}

func (x *OpenSyscallMsg) GetFilename() string {
	if x != nil {
		return x.Filename
	}
	return ""
}

func (x *OpenSyscallMsg) GetFlags() uint32 {
	if x != nil {
		return x.Flags
	}
	return 0
}

func (x *OpenSyscallMsg) GetMode() uint32 {
	if x != nil {
		return x.Mode
	}
	return 0
}

type SyscallMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SeqNum           uint64            `protobuf:"varint,1,opt,name=SeqNum,proto3" json:"SeqNum,omitempty"`
	Type             SyscallType       `protobuf:"varint,2,opt,name=Type,proto3,enum=ebpfless.SyscallType" json:"Type,omitempty"`
	PID              uint32            `protobuf:"varint,3,opt,name=PID,proto3" json:"PID,omitempty"`
	ContainerContext *ContainerContext `protobuf:"bytes,4,opt,name=ContainerContext,proto3" json:"ContainerContext,omitempty"`
	Exec             *ExecSyscallMsg   `protobuf:"bytes,5,opt,name=Exec,proto3" json:"Exec,omitempty"`
	Open             *OpenSyscallMsg   `protobuf:"bytes,6,opt,name=Open,proto3" json:"Open,omitempty"`
	Fork             *ForkSyscallMsg   `protobuf:"bytes,7,opt,name=Fork,proto3" json:"Fork,omitempty"`
	Exit             *ExitSyscallMsg   `protobuf:"bytes,8,opt,name=Exit,proto3" json:"Exit,omitempty"`
	Fcntl            *FcntlSyscallMsg  `protobuf:"bytes,9,opt,name=Fcntl,proto3" json:"Fcntl,omitempty"`
}

func (x *SyscallMsg) Reset() {
	*x = SyscallMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyscallMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyscallMsg) ProtoMessage() {}

func (x *SyscallMsg) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyscallMsg.ProtoReflect.Descriptor instead.
func (*SyscallMsg) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{6}
}

func (x *SyscallMsg) GetSeqNum() uint64 {
	if x != nil {
		return x.SeqNum
	}
	return 0
}

func (x *SyscallMsg) GetType() SyscallType {
	if x != nil {
		return x.Type
	}
	return SyscallType_Unknown
}

func (x *SyscallMsg) GetPID() uint32 {
	if x != nil {
		return x.PID
	}
	return 0
}

func (x *SyscallMsg) GetContainerContext() *ContainerContext {
	if x != nil {
		return x.ContainerContext
	}
	return nil
}

func (x *SyscallMsg) GetExec() *ExecSyscallMsg {
	if x != nil {
		return x.Exec
	}
	return nil
}

func (x *SyscallMsg) GetOpen() *OpenSyscallMsg {
	if x != nil {
		return x.Open
	}
	return nil
}

func (x *SyscallMsg) GetFork() *ForkSyscallMsg {
	if x != nil {
		return x.Fork
	}
	return nil
}

func (x *SyscallMsg) GetExit() *ExitSyscallMsg {
	if x != nil {
		return x.Exit
	}
	return nil
}

func (x *SyscallMsg) GetFcntl() *FcntlSyscallMsg {
	if x != nil {
		return x.Fcntl
	}
	return nil
}

type Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Response) Reset() {
	*x = Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_security_proto_ebpfless_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response.ProtoReflect.Descriptor instead.
func (*Response) Descriptor() ([]byte, []int) {
	return file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP(), []int{7}
}

var File_pkg_security_proto_ebpfless_service_proto protoreflect.FileDescriptor

var file_pkg_security_proto_ebpfless_service_proto_rawDesc = []byte{
	0x0a, 0x29, 0x70, 0x6b, 0x67, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x65, 0x62, 0x70,
	0x66, 0x6c, 0x65, 0x73, 0x73, 0x22, 0x66, 0x0a, 0x10, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x49, 0x44, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x49, 0x44, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a,
	0x03, 0x54, 0x61, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x54, 0x61, 0x67, 0x12,
	0x1c, 0x0a, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x09, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x22, 0x33, 0x0a,
	0x0f, 0x46, 0x63, 0x6e, 0x74, 0x6c, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67,
	0x12, 0x0e, 0x0a, 0x02, 0x46, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x46, 0x64,
	0x12, 0x10, 0x0a, 0x03, 0x43, 0x6d, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x43,
	0x6d, 0x64, 0x22, 0x54, 0x0a, 0x0e, 0x45, 0x78, 0x65, 0x63, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c,
	0x6c, 0x4d, 0x73, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x12, 0x0a, 0x04, 0x41, 0x72, 0x67, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04,
	0x41, 0x72, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x45, 0x6e, 0x76, 0x73, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x04, 0x45, 0x6e, 0x76, 0x73, 0x22, 0x24, 0x0a, 0x0e, 0x46, 0x6f, 0x72, 0x6b,
	0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x50, 0x50,
	0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x50, 0x50, 0x49, 0x44, 0x22, 0x10,
	0x0a, 0x0e, 0x45, 0x78, 0x69, 0x74, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67,
	0x22, 0x56, 0x0a, 0x0e, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d,
	0x73, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14,
	0x0a, 0x05, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x46,
	0x6c, 0x61, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x22, 0x92, 0x03, 0x0a, 0x0a, 0x53, 0x79, 0x73,
	0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x65, 0x71, 0x4e, 0x75,
	0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x53, 0x65, 0x71, 0x4e, 0x75, 0x6d, 0x12,
	0x29, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e,
	0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c,
	0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x50, 0x49,
	0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x50, 0x49, 0x44, 0x12, 0x46, 0x0a, 0x10,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73,
	0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x74, 0x65,
	0x78, 0x74, 0x52, 0x10, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x43, 0x6f, 0x6e,
	0x74, 0x65, 0x78, 0x74, 0x12, 0x2c, 0x0a, 0x04, 0x45, 0x78, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x18, 0x2e, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x45, 0x78,
	0x65, 0x63, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x45, 0x78,
	0x65, 0x63, 0x12, 0x2c, 0x0a, 0x04, 0x4f, 0x70, 0x65, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x18, 0x2e, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x4f, 0x70, 0x65, 0x6e,
	0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x4f, 0x70, 0x65, 0x6e,
	0x12, 0x2c, 0x0a, 0x04, 0x46, 0x6f, 0x72, 0x6b, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x46, 0x6f, 0x72, 0x6b, 0x53, 0x79,
	0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x46, 0x6f, 0x72, 0x6b, 0x12, 0x2c,
	0x0a, 0x04, 0x45, 0x78, 0x69, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x65,
	0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x45, 0x78, 0x69, 0x74, 0x53, 0x79, 0x73, 0x63,
	0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x45, 0x78, 0x69, 0x74, 0x12, 0x2f, 0x0a, 0x05,
	0x46, 0x63, 0x6e, 0x74, 0x6c, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x65, 0x62,
	0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x46, 0x63, 0x6e, 0x74, 0x6c, 0x53, 0x79, 0x73, 0x63,
	0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x52, 0x05, 0x46, 0x63, 0x6e, 0x74, 0x6c, 0x22, 0x0a, 0x0a,
	0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2a, 0x4d, 0x0a, 0x0b, 0x53, 0x79, 0x73,
	0x63, 0x61, 0x6c, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x6e, 0x6b, 0x6e,
	0x6f, 0x77, 0x6e, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x45, 0x78, 0x65, 0x63, 0x10, 0x01, 0x12,
	0x08, 0x0a, 0x04, 0x46, 0x6f, 0x72, 0x6b, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x4f, 0x70, 0x65,
	0x6e, 0x10, 0x03, 0x12, 0x08, 0x0a, 0x04, 0x45, 0x78, 0x69, 0x74, 0x10, 0x04, 0x12, 0x09, 0x0a,
	0x05, 0x46, 0x63, 0x6e, 0x74, 0x6c, 0x10, 0x05, 0x32, 0x50, 0x0a, 0x10, 0x53, 0x79, 0x73, 0x63,
	0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x3c, 0x0a, 0x0e,
	0x53, 0x65, 0x6e, 0x64, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x4d, 0x73, 0x67, 0x12, 0x14,
	0x2e, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c,
	0x6c, 0x4d, 0x73, 0x67, 0x1a, 0x12, 0x2e, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x2e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x1d, 0x5a, 0x1b, 0x70, 0x6b,
	0x67, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x65, 0x62, 0x70, 0x66, 0x6c, 0x65, 0x73, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_pkg_security_proto_ebpfless_service_proto_rawDescOnce sync.Once
	file_pkg_security_proto_ebpfless_service_proto_rawDescData = file_pkg_security_proto_ebpfless_service_proto_rawDesc
)

func file_pkg_security_proto_ebpfless_service_proto_rawDescGZIP() []byte {
	file_pkg_security_proto_ebpfless_service_proto_rawDescOnce.Do(func() {
		file_pkg_security_proto_ebpfless_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_security_proto_ebpfless_service_proto_rawDescData)
	})
	return file_pkg_security_proto_ebpfless_service_proto_rawDescData
}

var file_pkg_security_proto_ebpfless_service_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pkg_security_proto_ebpfless_service_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_pkg_security_proto_ebpfless_service_proto_goTypes = []interface{}{
	(SyscallType)(0),         // 0: ebpfless.SyscallType
	(*ContainerContext)(nil), // 1: ebpfless.ContainerContext
	(*FcntlSyscallMsg)(nil),  // 2: ebpfless.FcntlSyscallMsg
	(*ExecSyscallMsg)(nil),   // 3: ebpfless.ExecSyscallMsg
	(*ForkSyscallMsg)(nil),   // 4: ebpfless.ForkSyscallMsg
	(*ExitSyscallMsg)(nil),   // 5: ebpfless.ExitSyscallMsg
	(*OpenSyscallMsg)(nil),   // 6: ebpfless.OpenSyscallMsg
	(*SyscallMsg)(nil),       // 7: ebpfless.SyscallMsg
	(*Response)(nil),         // 8: ebpfless.Response
}
var file_pkg_security_proto_ebpfless_service_proto_depIdxs = []int32{
	0, // 0: ebpfless.SyscallMsg.Type:type_name -> ebpfless.SyscallType
	1, // 1: ebpfless.SyscallMsg.ContainerContext:type_name -> ebpfless.ContainerContext
	3, // 2: ebpfless.SyscallMsg.Exec:type_name -> ebpfless.ExecSyscallMsg
	6, // 3: ebpfless.SyscallMsg.Open:type_name -> ebpfless.OpenSyscallMsg
	4, // 4: ebpfless.SyscallMsg.Fork:type_name -> ebpfless.ForkSyscallMsg
	5, // 5: ebpfless.SyscallMsg.Exit:type_name -> ebpfless.ExitSyscallMsg
	2, // 6: ebpfless.SyscallMsg.Fcntl:type_name -> ebpfless.FcntlSyscallMsg
	7, // 7: ebpfless.SyscallMsgStream.SendSyscallMsg:input_type -> ebpfless.SyscallMsg
	8, // 8: ebpfless.SyscallMsgStream.SendSyscallMsg:output_type -> ebpfless.Response
	8, // [8:9] is the sub-list for method output_type
	7, // [7:8] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_pkg_security_proto_ebpfless_service_proto_init() }
func file_pkg_security_proto_ebpfless_service_proto_init() {
	if File_pkg_security_proto_ebpfless_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ContainerContext); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FcntlSyscallMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExecSyscallMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ForkSyscallMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExitSyscallMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OpenSyscallMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyscallMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_security_proto_ebpfless_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Response); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_security_proto_ebpfless_service_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_security_proto_ebpfless_service_proto_goTypes,
		DependencyIndexes: file_pkg_security_proto_ebpfless_service_proto_depIdxs,
		EnumInfos:         file_pkg_security_proto_ebpfless_service_proto_enumTypes,
		MessageInfos:      file_pkg_security_proto_ebpfless_service_proto_msgTypes,
	}.Build()
	File_pkg_security_proto_ebpfless_service_proto = out.File
	file_pkg_security_proto_ebpfless_service_proto_rawDesc = nil
	file_pkg_security_proto_ebpfless_service_proto_goTypes = nil
	file_pkg_security_proto_ebpfless_service_proto_depIdxs = nil
}
