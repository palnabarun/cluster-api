//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FakeRequest) DeepCopyInto(out *FakeRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.Cluster.DeepCopyInto(&out.Cluster)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FakeRequest.
func (in *FakeRequest) DeepCopy() *FakeRequest {
	if in == nil {
		return nil
	}
	out := new(FakeRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FakeRequest) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FakeResponse) DeepCopyInto(out *FakeResponse) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.CommonResponse = in.CommonResponse
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FakeResponse.
func (in *FakeResponse) DeepCopy() *FakeResponse {
	if in == nil {
		return nil
	}
	out := new(FakeResponse)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FakeResponse) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecondFakeRequest) DeepCopyInto(out *SecondFakeRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.Cluster.DeepCopyInto(&out.Cluster)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecondFakeRequest.
func (in *SecondFakeRequest) DeepCopy() *SecondFakeRequest {
	if in == nil {
		return nil
	}
	out := new(SecondFakeRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecondFakeRequest) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecondFakeResponse) DeepCopyInto(out *SecondFakeResponse) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.CommonResponse = in.CommonResponse
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecondFakeResponse.
func (in *SecondFakeResponse) DeepCopy() *SecondFakeResponse {
	if in == nil {
		return nil
	}
	out := new(SecondFakeResponse)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecondFakeResponse) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
