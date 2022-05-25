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
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	refdocker "github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nerdctl/pkg/containerinspector"
	"github.com/containerd/nerdctl/pkg/inspecttypes/dockercompat"
	"github.com/containerd/nerdctl/pkg/labels"
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

func (x *containerInspector) Handler(ctx context.Context, found Found) error {
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

func formatSlice(x []interface{}) (string, error) {
	var tmpl *template.Template
	var err error
	tmpl, err = parseTemplate("{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}")
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
	walker := ContainerWalker{
		Client:  c.client,
		OnFound: f.Handler,
	}
	n, err := walker.Walk(ctx, containerName)
	if err != nil {
		return "", "", err
	} else if n == 0 {
		return "", "", fmt.Errorf("no such object %s", containerName)
	}

	ip, err := formatSlice(f.entries)
	if err != nil {
		return "", "", err
	}
	return ip, "", nil
}

type Found struct {
	Container  containerd.Container
	Req        string // The raw request string. name, short ID, or long ID.
	MatchIndex int    // Begins with 0, up to MatchCount - 1.
	MatchCount int    // 1 on exact match. > 1 on ambiguous match. Never be <= 0.
}

type OnFound func(ctx context.Context, found Found) error

type ContainerWalker struct {
	Client  *containerd.Client
	OnFound OnFound
}

// Walk walks containers and calls w.OnFound .
// Req is name, short ID, or long ID.
// Returns the number of the found entries.
func (w *ContainerWalker) Walk(ctx context.Context, req string) (int, error) {
	if strings.HasPrefix(req, "k8s://") {
		return -1, fmt.Errorf("specifying \"k8s://...\" form is not supported (Hint: specify ID instead): %q", req)
	}
	filters := []string{
		fmt.Sprintf("labels.%q==%s", labels.Name, req),
		fmt.Sprintf("id~=^%s.*$", regexp.QuoteMeta(req)),
	}

	containers, err := w.Client.Containers(ctx, filters...)
	if err != nil {
		return -1, err
	}

	matchCount := len(containers)
	for i, c := range containers {
		f := Found{
			Container:  c,
			Req:        req,
			MatchIndex: i,
			MatchCount: matchCount,
		}
		e := w.OnFound(ctx, f)
		if e != nil {
			return -1, e
		} else {
			return 1, nil
		}
	}
	return matchCount, nil
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
