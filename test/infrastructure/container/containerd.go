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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	refdocker "github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nerdctl/pkg/containerinspector"
	"github.com/containerd/nerdctl/pkg/idutil/containerwalker"
	"github.com/containerd/nerdctl/pkg/inspecttypes/dockercompat"
	"github.com/docker/cli/templates"
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

func (c *containerdRuntime) GetHostPort(ctx context.Context, containerName, portAndProtocol string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

type containerInspector struct {
	entries []interface{}
}

func (x *containerInspector) Handler(ctx context.Context, found containerwalker.Found) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	n, err := containerinspector.Inspect(ctx, found.Container)
	if err != nil {
		return err
	}

	d, err := dockercompat.ContainerFromNative(n)
	if err != nil {
		return err
	}
	x.entries = append(x.entries, d)
	return nil
}

func formatSlice(x []interface{}, format string) (string, error) {
	var tmpl *template.Template
	var err error
	tmpl, err = parseTemplate(format)
	if err != nil {
		return "", err
	}
	for _, f := range x {
		var b bytes.Buffer
		if err := tmpl.Execute(&b, f); err != nil {
			if _, ok := err.(template.ExecError); ok {
				// FallBack to Raw Format
				if err = tryRawFormat(&b, f, tmpl); err != nil {
					return "", err
				}
			}
		}
		return b.String(), nil
	}
	return "", nil
}

func tryRawFormat(b *bytes.Buffer, f interface{}, tmpl *template.Template) error {
	m, err := json.MarshalIndent(f, "", "    ")
	if err != nil {
		return err
	}

	var raw interface{}
	rdr := bytes.NewReader(m)
	dec := json.NewDecoder(rdr)
	dec.UseNumber()

	if rawErr := dec.Decode(&raw); rawErr != nil {
		return fmt.Errorf("unable to read inspect data: %v", rawErr)
	}

	tmplMissingKey := tmpl.Option("missingkey=error")
	if rawErr := tmplMissingKey.Execute(b, raw); rawErr != nil {
		return fmt.Errorf("Template parsing error: %v", rawErr)
	}

	return nil
}

// parseTemplate wraps github.com/docker/cli/templates.Parse() to allow `json` as an alias of `{{json .}}`.
// parseTemplate can be removed when https://github.com/docker/cli/pull/3355 gets merged and tagged (Docker 22.XX).
func parseTemplate(format string) (*template.Template, error) {
	aliases := map[string]string{
		"json": "{{json .}}",
	}
	if alias, ok := aliases[format]; ok {
		format = alias
	}
	return templates.Parse(format)
}

func (c *containerdRuntime) GetContainerIPs(ctx context.Context, containerName string) (string, string, error) {
	f := &containerInspector{}
	walker := containerwalker.ContainerWalker{
		Client:  c.client,
		OnFound: f.Handler,
	}
	n, err := walker.Walk(ctx, containerName)
	if err != nil {
		return "", "", err
	} else if n == 0 {
		return "", "", fmt.Errorf("no such object %s", containerName)
	}

	format := "{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}"
	ip, err := formatSlice(f.entries, format)
	if err != nil {
		return "", "", err
	}

	format = "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
	ipv6, err := formatSlice(f.entries, format)
	if err != nil {
		return "", "", err
	}

	return ip, ipv6, nil
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
