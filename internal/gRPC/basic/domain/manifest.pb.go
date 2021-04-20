// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.14.0
// source: compliance-hub-plugin-trivy/internal/proto-files/basic/domain/manifest.proto

package domain

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

type Command struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Command string `protobuf:"bytes,1,opt,name=command,proto3" json:"command,omitempty"`
}

func (x *Command) Reset() {
	*x = Command{}
	if protoimpl.UnsafeEnabled {
		mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command) ProtoMessage() {}

func (x *Command) ProtoReflect() protoreflect.Message {
	mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Command.ProtoReflect.Descriptor instead.
func (*Command) Descriptor() ([]byte, []int) {
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP(), []int{0}
}

func (x *Command) GetCommand() string {
	if x != nil {
		return x.Command
	}
	return ""
}

type AssetType struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
}

func (x *AssetType) Reset() {
	*x = AssetType{}
	if protoimpl.UnsafeEnabled {
		mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssetType) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssetType) ProtoMessage() {}

func (x *AssetType) ProtoReflect() protoreflect.Message {
	mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssetType.ProtoReflect.Descriptor instead.
func (*AssetType) Descriptor() ([]byte, []int) {
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP(), []int{1}
}

func (x *AssetType) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

type AssetRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AssetType      *AssetType `protobuf:"bytes,1,opt,name=assetType,proto3" json:"assetType,omitempty"`
	Role           string     `protobuf:"bytes,2,opt,name=role,proto3" json:"role,omitempty"`
	RequestsAssets bool       `protobuf:"varint,3,opt,name=requestsAssets,proto3" json:"requestsAssets,omitempty"`
	Command        *Command   `protobuf:"bytes,4,opt,name=command,proto3" json:"command,omitempty"`
}

func (x *AssetRole) Reset() {
	*x = AssetRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssetRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssetRole) ProtoMessage() {}

func (x *AssetRole) ProtoReflect() protoreflect.Message {
	mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssetRole.ProtoReflect.Descriptor instead.
func (*AssetRole) Descriptor() ([]byte, []int) {
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP(), []int{2}
}

func (x *AssetRole) GetAssetType() *AssetType {
	if x != nil {
		return x.AssetType
	}
	return nil
}

func (x *AssetRole) GetRole() string {
	if x != nil {
		return x.Role
	}
	return ""
}

func (x *AssetRole) GetRequestsAssets() bool {
	if x != nil {
		return x.RequestsAssets
	}
	return false
}

func (x *AssetRole) GetCommand() *Command {
	if x != nil {
		return x.Command
	}
	return nil
}

type Manifest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid       string       `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Name       string       `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	AssetRoles []*AssetRole `protobuf:"bytes,3,rep,name=assetRoles,proto3" json:"assetRoles,omitempty"`
	Commands   []*Command   `protobuf:"bytes,4,rep,name=commands,proto3" json:"commands,omitempty"`
}

func (x *Manifest) Reset() {
	*x = Manifest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Manifest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Manifest) ProtoMessage() {}

func (x *Manifest) ProtoReflect() protoreflect.Message {
	mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Manifest.ProtoReflect.Descriptor instead.
func (*Manifest) Descriptor() ([]byte, []int) {
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP(), []int{3}
}

func (x *Manifest) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Manifest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Manifest) GetAssetRoles() []*AssetRole {
	if x != nil {
		return x.AssetRoles
	}
	return nil
}

func (x *Manifest) GetCommands() []*Command {
	if x != nil {
		return x.Commands
	}
	return nil
}

type Asset struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid           string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Type           string `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	SubType        string `protobuf:"bytes,3,opt,name=subType,proto3" json:"subType,omitempty"`
	Identifier     string `protobuf:"bytes,4,opt,name=identifier,proto3" json:"identifier,omitempty"`
	Status         string `protobuf:"bytes,5,opt,name=status,proto3" json:"status,omitempty"`
	AttributesUuid string `protobuf:"bytes,6,opt,name=attributesUuid,proto3" json:"attributesUuid,omitempty"`
	Attributes     []byte `protobuf:"bytes,7,opt,name=attributes,proto3" json:"attributes,omitempty"`
}

func (x *Asset) Reset() {
	*x = Asset{}
	if protoimpl.UnsafeEnabled {
		mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Asset) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Asset) ProtoMessage() {}

func (x *Asset) ProtoReflect() protoreflect.Message {
	mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Asset.ProtoReflect.Descriptor instead.
func (*Asset) Descriptor() ([]byte, []int) {
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP(), []int{4}
}

func (x *Asset) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Asset) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Asset) GetSubType() string {
	if x != nil {
		return x.SubType
	}
	return ""
}

func (x *Asset) GetIdentifier() string {
	if x != nil {
		return x.Identifier
	}
	return ""
}

func (x *Asset) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *Asset) GetAttributesUuid() string {
	if x != nil {
		return x.AttributesUuid
	}
	return ""
}

func (x *Asset) GetAttributes() []byte {
	if x != nil {
		return x.Attributes
	}
	return nil
}

type Account struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid        string `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Name        string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Provider    string `protobuf:"bytes,3,opt,name=provider,proto3" json:"provider,omitempty"`
	Credentials string `protobuf:"bytes,4,opt,name=credentials,proto3" json:"credentials,omitempty"`
}

func (x *Account) Reset() {
	*x = Account{}
	if protoimpl.UnsafeEnabled {
		mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Account) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Account) ProtoMessage() {}

func (x *Account) ProtoReflect() protoreflect.Message {
	mi := &file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Account.ProtoReflect.Descriptor instead.
func (*Account) Descriptor() ([]byte, []int) {
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP(), []int{5}
}

func (x *Account) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Account) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Account) GetProvider() string {
	if x != nil {
		return x.Provider
	}
	return ""
}

func (x *Account) GetCredentials() string {
	if x != nil {
		return x.Credentials
	}
	return ""
}

var File_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto protoreflect.FileDescriptor

var file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDesc = []byte{
	0x0a, 0x4c, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x68, 0x75, 0x62,
	0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2d, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2f, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2d, 0x66, 0x69, 0x6c,
	0x65, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x69, 0x63, 0x2f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2f,
	0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x22, 0x23, 0x0a, 0x07, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
	0x64, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x22, 0x1f, 0x0a, 0x09, 0x41,
	0x73, 0x73, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x22, 0xa3, 0x01, 0x0a,
	0x09, 0x41, 0x73, 0x73, 0x65, 0x74, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x2f, 0x0a, 0x09, 0x61, 0x73,
	0x73, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x41, 0x73, 0x73, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65,
	0x52, 0x09, 0x61, 0x73, 0x73, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x72,
	0x6f, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12,
	0x26, 0x0a, 0x0e, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x41, 0x73, 0x73, 0x65, 0x74,
	0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x73, 0x41, 0x73, 0x73, 0x65, 0x74, 0x73, 0x12, 0x29, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61,
	0x6e, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69,
	0x6e, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61,
	0x6e, 0x64, 0x22, 0x92, 0x01, 0x0a, 0x08, 0x4d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75,
	0x75, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x31, 0x0a, 0x0a, 0x61, 0x73, 0x73, 0x65, 0x74,
	0x52, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x64, 0x6f,
	0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x41, 0x73, 0x73, 0x65, 0x74, 0x52, 0x6f, 0x6c, 0x65, 0x52, 0x0a,
	0x61, 0x73, 0x73, 0x65, 0x74, 0x52, 0x6f, 0x6c, 0x65, 0x73, 0x12, 0x2b, 0x0a, 0x08, 0x63, 0x6f,
	0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x08, 0x63,
	0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x73, 0x22, 0xc9, 0x01, 0x0a, 0x05, 0x41, 0x73, 0x73, 0x65,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x62,
	0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65,
	0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x26, 0x0a, 0x0e, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x55, 0x75, 0x69, 0x64, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0e, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x55,
	0x75, 0x69, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
	0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x22, 0x6f, 0x0a, 0x07, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75,
	0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x73, 0x42, 0x38, 0x5a, 0x36, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e,
	0x63, 0x65, 0x2d, 0x68, 0x75, 0x62, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2d, 0x74, 0x72,
	0x69, 0x76, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x52, 0x50,
	0x43, 0x2f, 0x62, 0x61, 0x73, 0x69, 0x63, 0x2f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescOnce sync.Once
	file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescData = file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDesc
)

func file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescGZIP() []byte {
	file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescOnce.Do(func() {
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescData = protoimpl.X.CompressGZIP(file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescData)
	})
	return file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDescData
}

var file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_goTypes = []interface{}{
	(*Command)(nil),   // 0: domain.Command
	(*AssetType)(nil), // 1: domain.AssetType
	(*AssetRole)(nil), // 2: domain.AssetRole
	(*Manifest)(nil),  // 3: domain.Manifest
	(*Asset)(nil),     // 4: domain.Asset
	(*Account)(nil),   // 5: domain.Account
}
var file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_depIdxs = []int32{
	1, // 0: domain.AssetRole.assetType:type_name -> domain.AssetType
	0, // 1: domain.AssetRole.command:type_name -> domain.Command
	2, // 2: domain.Manifest.assetRoles:type_name -> domain.AssetRole
	0, // 3: domain.Manifest.commands:type_name -> domain.Command
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_init() }
func file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_init() {
	if File_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Command); i {
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
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssetType); i {
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
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssetRole); i {
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
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Manifest); i {
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
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Asset); i {
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
		file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Account); i {
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
			RawDescriptor: file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_goTypes,
		DependencyIndexes: file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_depIdxs,
		MessageInfos:      file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_msgTypes,
	}.Build()
	File_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto = out.File
	file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_rawDesc = nil
	file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_goTypes = nil
	file_compliance_hub_plugin_trivy_internal_proto_files_basic_domain_manifest_proto_depIdxs = nil
}
