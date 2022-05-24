/*
Copyright 2022 The Kubernetes Authors.

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

// Package container provides an interface for interacting with containerd
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	refdocker "github.com/containerd/containerd/reference/docker"
	gocni "github.com/containerd/go-cni"
	"github.com/containerd/nerdctl/pkg/idutil/containerwalker"
	"github.com/containerd/nerdctl/pkg/labels"
)

type containerdRuntime struct {
	client    *containerd.Client
	namespace string
}

func NewContainerdClient(socketPath string, namespace string) (Runtime, error) {
	client, err := containerd.New(socketPath)
	if err != nil {
		return &containerdRuntime{}, fmt.Errorf("failed to create containerd client")
	}

	return &containerdRuntime{client: client, namespace: namespace}, nil
}

func (c *containerdRuntime) SaveContainerImage(ctx context.Context, image, dest string) error {
	return fmt.Errorf("not implemented")
}

func (c *containerdRuntime) PullContainerImageIfNotExists(ctx context.Context, image string) error {
	ctx = namespaces.WithNamespace(ctx, c.namespace)

	ref, err := refdocker.ParseDockerRef(image)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %v", err)
	}

	images, err := c.client.ListImages(ctx, fmt.Sprintf("name==%s", ref.String()))
	if err != nil {
		return fmt.Errorf("error listing images: %v", err)
	}

	// image already exists
	if len(images) > 0 {
		return nil
	}

	if _, err := c.client.Pull(ctx, image); err != nil {
		return fmt.Errorf("error pulling image: %v", err)
	}

	return nil
}

// type Found struct {
// 	Container  containerd.Container
// 	Req        string // The raw request string. name, short ID, or long ID.
// 	MatchIndex int    // Begins with 0, up to MatchCount - 1.
// 	MatchCount int    // 1 on exact match. > 1 on ambiguous match. Never be <= 0.
// }

// type OnFound func(ctx context.Context, found Found) error

// type ContainerWalker struct {
// 	Client  *containerd.Client
// 	OnFound OnFound
// }

// Walk walks containers and calls w.OnFound .
// Req is name, short ID, or long ID.
// Returns the number of the found entries.
// func (w *ContainerWalker) Walk(ctx context.Context, req string) (int, error) {
// 	if strings.HasPrefix(req, "k8s://") {
// 		return -1, fmt.Errorf("specifying \"k8s://...\" form is not supported (Hint: specify ID instead): %q", req)
// 	}
// 	filters := []string{
// 		fmt.Sprintf("labels.%q==%s", labels.Name, req),
// 		fmt.Sprintf("id~=^%s.*$", regexp.QuoteMeta(req)),
// 	}

// 	containers, err := w.Client.Containers(ctx, filters...)
// 	if err != nil {
// 		return -1, err
// 	}

// 	matchCount := len(containers)
// 	for i, c := range containers {
// 		f := Found{
// 			Container:  c,
// 			Req:        req,
// 			MatchIndex: i,
// 			MatchCount: matchCount,
// 		}
// 		e := w.OnFound(ctx, f)
// 		if e != nil {
// 			return -1, e
// 		} else {
// 			return 1, nil
// 		}
// 	}
// 	return matchCount, nil
// }

func (c *containerdRuntime) GetHostPort(ctx context.Context, containerName, portAndProtocol string) (string, error) {
	argPort := -1
	argProto := ""
	portProto := portAndProtocol
	var err error

	if portProto != "" {
		splitBySlash := strings.Split(portProto, "/")
		argPort, err = strconv.Atoi(splitBySlash[0])
		if err != nil {
			return "", err
		}
		if argPort <= 0 {
			return "", fmt.Errorf("unexpected port %d", argPort)
		}
		switch len(splitBySlash) {
		case 1:
			argProto = "tcp"
		case 2:
			argProto = strings.ToLower(splitBySlash[1])
		default:
			return "", fmt.Errorf("failed to parse %q", portProto)
		}
	}

	var port string
	walker := &containerwalker.ContainerWalker{
		Client: c.client,
		OnFound: func(ctx context.Context, found containerwalker.Found) error {
			if found.MatchCount > 1 {
				return fmt.Errorf("ambiguous ID %q", found.Req)
			}
			port, err = printPort(ctx, found.Req, found.Container, argPort, argProto)
			if err != nil {
				return err
			}
			return nil
		},
	}

	n, err := walker.Walk(ctx, containerName)
	if err != nil {
		return "", err
	} else if n == 0 {
		return "", fmt.Errorf("no such container %s", containerName)
	}
	return port, nil
}

func printPort(ctx context.Context, containerName string, container containerd.Container, argPort int, argProto string) (string, error) {
	l, err := container.Labels(ctx)
	if err != nil {
		return "", err
	}
	portsJSON := l[labels.Ports]
	if portsJSON == "" {
		return "", nil
	}
	var ports []gocni.PortMapping
	if err := json.Unmarshal([]byte(portsJSON), &ports); err != nil {
		return "", err
	}
	// Loop through the ports and return the first HostPort.
	for _, p := range ports {
		if p.ContainerPort == int32(argPort) && strings.ToLower(p.Protocol) == argProto {
			return strconv.Itoa(int(p.HostPort)), nil
		}
	}
	return "", fmt.Errorf("no host port found for load balancer %q", containerName)
}

func (c *containerdRuntime) GetContainerIPs(ctx context.Context, containerName string) (string, string, error) {
	return "", "", fmt.Errorf("not implemented")
}

func (c *containerdRuntime) ExecContainer(ctx context.Context, containerName string, config *ExecContainerInput, command string, args ...string) error {
	return fmt.Errorf("not implemented")
}

func (c *containerdRuntime) RunContainer(ctx context.Context, runConfig *RunContainerInput, output io.Writer) error {
	return fmt.Errorf("not implemented")
}

func (c *containerdRuntime) ListContainers(ctx context.Context, filters FilterBuilder) ([]Container, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *containerdRuntime) ContainerDebugInfo(ctx context.Context, containerName string, w io.Writer) error {
	return fmt.Errorf("not implemented")
}

func (c *containerdRuntime) DeleteContainer(ctx context.Context, containerName string) error {
	return fmt.Errorf("not implemented")
}

func (c *containerdRuntime) KillContainer(ctx context.Context, containerName, signal string) error {
	return fmt.Errorf("not implemented")
}
