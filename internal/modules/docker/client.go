package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// SocketPaths are the places where the engine socket is looked for.
var SocketPaths = []string{"/run/docker.sock", "/var/run/docker.sock"}

// apiVersion is pinned deliberately. Without pinning the engine answers
// with the default version, which changes with a Docker update - and then
// the meaning of the fields being read changes and nobody notices.
const apiVersion = "v1.41"

// ErrUnavailable means an engine that cannot be queried.
var ErrUnavailable = errors.New("the container engine is unavailable")

// Client talks to the Engine API over a unix socket.
//
// The client does not accept an arbitrary path. Every operation has its
// own method and its own parameters: passing a path from outside would mean
// any engine API could be called through the helper, and that is
// equivalent to root.
type Client struct {
	http   *http.Client
	socket string
}

// New creates a client for the first socket found.
func New() (*Client, error) {
	for _, path := range SocketPaths {
		info, err := os.Stat(path)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		return NewAt(path), nil
	}
	return nil, fmt.Errorf("%w: no engine socket", ErrUnavailable)
}

// NewAt creates a client for the given socket.
func NewAt(socket string) *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &Client{
		socket: socket,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
				// The engine is local; none of these connections leaves the
				// host, so the pool can be small.
				MaxIdleConns:    2,
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// Version returns the engine version and its API version.
func (c *Client) Version(ctx context.Context) (engine, api string, err error) {
	var result struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	if err := c.get(ctx, "/version", nil, &result); err != nil {
		return "", "", err
	}
	return result.Version, result.APIVersion, nil
}

// get performs a query to a path built in this package. The path never
// comes from outside the module.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.call(ctx, http.MethodGet, path, query, out)
}

func (c *Client) call(ctx context.Context, method, path string, query url.Values, out any) error {
	target := "http://docker/" + apiVersion + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnavailable, shortenError(err))
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		// The engine error text can be long; its beginning goes into the
		// result so the message stays readable.
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("the engine answered %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	// Engine responses can be big: the image list on a build host can run
	// to megabytes. The limit protects the memory of the agent and the
	// helper.
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
}

// errSizeLimit means a stream cut off by the limit, not a read failure.
var errSizeLimit = errors.New("the read size limit was reached")

// stream reads the response line by line and hands each to the callback.
//
// It serves the only query that answers with a stream instead of one value:
// the event log. The byte limit is hard - a host on which something comes
// up in a loop can produce events faster than the panel can read them. The
// callback returning false ends the read.
func (c *Client) stream(ctx context.Context, path string, query url.Values,
	next func(line []byte) bool, byteLimit int64) error {
	target := "http://docker/" + apiVersion + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnavailable, shortenError(err))
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("the engine answered %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}

	scanner := bufio.NewScanner(io.LimitReader(response.Body, byteLimit))
	// A single event can be long: the engine attaches all the object's
	// labels to it.
	scanner.Buffer(make([]byte, 0, 8<<10), 256<<10)
	var read int64
	for scanner.Scan() {
		line := scanner.Bytes()
		read += int64(len(line)) + 1
		if len(line) == 0 {
			continue
		}
		if !next(line) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if read >= byteLimit {
		return errSizeLimit
	}
	return nil
}

// shortenError strips the repetitive HTTP transport prefix that adds
// nothing for the operator from the message.
func shortenError(err error) string {
	text := err.Error()
	if index := strings.LastIndex(text, ": "); index > 0 && index+2 < len(text) {
		return text[index+2:]
	}
	return text
}

// Containers returns the host containers. all includes stopped ones too: a
// stopped container is a fact about the host, not its absence.
func (c *Client) Containers(ctx context.Context, all bool) ([]Container, error) {
	query := url.Values{}
	if all {
		query.Set("all", "1")
	}
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Created int64             `json:"Created"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort uint16 `json:"PrivatePort"`
			PublicPort  uint16 `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		Mounts []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]struct {
				NetworkID         string   `json:"NetworkID"`
				IPAddress         string   `json:"IPAddress"`
				GlobalIPv6Address string   `json:"GlobalIPv6Address"`
				Aliases           []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := c.get(ctx, "/containers/json", query, &raw); err != nil {
		return nil, err
	}

	containers := make([]Container, 0, len(raw))
	for _, entry := range raw {
		container := Container{
			ID:          entry.ID,
			Name:        containerName(entry.Names),
			Image:       entry.Image,
			ImageDigest: entry.ImageID,
			State:       entry.State,
			Status:      entry.Status,
			CreatedAt:   time.Unix(entry.Created, 0).UTC(),
			Labels:      labelsWithoutSecrets(entry.Labels),
			Compose:     composeMembership(entry.Labels),
		}
		for _, port := range entry.Ports {
			container.Ports = append(container.Ports, Port{
				HostIP: port.IP, HostPort: port.PublicPort,
				ContainerPort: port.PrivatePort, Protocol: port.Type,
			})
		}
		for _, mount := range entry.Mounts {
			container.Mounts = append(container.Mounts, Mount{
				Type: mount.Type, Name: mount.Name, Source: mount.Source,
				Destination: mount.Destination, ReadOnly: !mount.RW,
			})
		}
		// Network membership is read from here, not from the network list:
		// the engine returns an empty container map in the network list, so
		// every network would look unused.
		for name, network := range entry.NetworkSettings.Networks {
			container.Networks = append(container.Networks, ContainerNetwork{
				Name: name, ID: network.NetworkID, IPv4: network.IPAddress,
				IPv6: network.GlobalIPv6Address, Aliases: network.Aliases,
			})
		}
		sort.Slice(container.Networks, func(i, j int) bool {
			return container.Networks[i].Name < container.Networks[j].Name
		})
		containers = append(containers, container)
	}
	return containers, nil
}

// Inspect supplements a container with data the list does not report: the
// health state and the restart counter. Only the containers for which it
// matters are queried - a full inspect of the whole list at every cycle
// would load the host.
func (c *Client) Inspect(ctx context.Context, id string) (health string, restarts int, err error) {
	var details struct {
		RestartCount int `json:"RestartCount"`
		State        struct {
			Health *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	if err := c.get(ctx, "/containers/"+id+"/json", nil, &details); err != nil {
		return "", 0, err
	}
	if details.State.Health != nil {
		health = details.State.Health.Status
	}
	return health, details.RestartCount, nil
}

// Images returns the images present on the host.
func (c *Client) Images(ctx context.Context) ([]Image, error) {
	var raw []struct {
		ID         string   `json:"Id"`
		RepoTags   []string `json:"RepoTags"`
		RepoDig    []string `json:"RepoDigests"`
		Size       int64    `json:"Size"`
		Created    int64    `json:"Created"`
		Containers int64    `json:"Containers"`
	}
	if err := c.get(ctx, "/images/json", nil, &raw); err != nil {
		return nil, err
	}
	images := make([]Image, 0, len(raw))
	for _, entry := range raw {
		images = append(images, Image{
			ID: entry.ID, Tags: skipUntagged(entry.RepoTags), Digests: entry.RepoDig,
			SizeBytes: entry.Size, CreatedAt: time.Unix(entry.Created, 0).UTC(),
			// The engine returns -1 when the container count was not
			// computed. Unknown usage must not look like an unused image,
			// because that is the one that goes under the prune.
			InUse: entry.Containers != 0,
		})
	}
	return images, nil
}

// Networks returns the Docker networks.
//
// Network usage does not come from here: the engine returns an empty
// container map in the network list, so every network would look unused.
// The collector derives it from the container list.
func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var raw []struct {
		ID         string    `json:"Id"`
		Name       string    `json:"Name"`
		Driver     string    `json:"Driver"`
		Scope      string    `json:"Scope"`
		Created    time.Time `json:"Created"`
		EnableIPv6 bool      `json:"EnableIPv6"`
		Internal   bool      `json:"Internal"`
		Attachable bool      `json:"Attachable"`
		Ingress    bool      `json:"Ingress"`
		IPAM       struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.get(ctx, "/networks", nil, &raw); err != nil {
		return nil, err
	}
	networks := make([]Network, 0, len(raw))
	for _, entry := range raw {
		network := Network{
			ID: entry.ID, Name: entry.Name, Driver: entry.Driver, Scope: entry.Scope,
			CreatedAt: entry.Created.UTC(), IPv6: entry.EnableIPv6,
			Internal: entry.Internal, Attachable: entry.Attachable, Ingress: entry.Ingress,
			Labels:     labelsWithoutSecrets(entry.Labels),
			Predefined: predefinedNetwork(entry.Name),
			Compose:    entry.Labels["com.docker.compose.project"],
		}
		for _, config := range entry.IPAM.Config {
			if config.Subnet != "" {
				network.Subnets = append(network.Subnets, config.Subnet)
			}
			if config.Gateway != "" {
				network.Gateways = append(network.Gateways, config.Gateway)
			}
		}
		networks = append(networks, network)
	}
	sort.Slice(networks, func(i, j int) bool { return networks[i].Name < networks[j].Name })
	return networks, nil
}

// predefinedNetwork says whether the network belongs to the engine. The
// engine does not allow removing it, so the panel must neither propose nor
// try that.
func predefinedNetwork(name string) bool {
	switch name {
	case "bridge", "host", "none":
		return true
	}
	return false
}

// Volumes returns the Docker volumes.
//
// Usage and size do not come from this query: the engine reports UsageData
// only with a separate, expensive disk usage computation. The collector
// derives usage from the container mounts, and the size stays unknown with
// a stated reason - zero would suggest an empty volume ready to be deleted.
func (c *Client) Volumes(ctx context.Context) ([]Volume, error) {
	var response struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Scope      string            `json:"Scope"`
			CreatedAt  time.Time         `json:"CreatedAt"`
			Labels     map[string]string `json:"Labels"`
			Options    map[string]string `json:"Options"`
			UsageData  *struct {
				Size     int64 `json:"Size"`
				RefCount int64 `json:"RefCount"`
			} `json:"UsageData"`
		} `json:"Volumes"`
	}
	if err := c.get(ctx, "/volumes", nil, &response); err != nil {
		return nil, err
	}
	volumes := make([]Volume, 0, len(response.Volumes))
	for _, entry := range response.Volumes {
		volume := Volume{
			Name: entry.Name, Driver: entry.Driver, Mountpoint: entry.Mountpoint,
			Scope: entry.Scope, CreatedAt: entry.CreatedAt.UTC(),
			Labels:  labelsWithoutSecrets(entry.Labels),
			Options: entry.Options,
			Compose: entry.Labels["com.docker.compose.project"],
			// The size is computed by walking the whole volume, so the
			// engine does not report it in this query.
			SizeReason: "the engine does not report the size without a disk usage computation",
		}
		if entry.UsageData != nil && entry.UsageData.Size >= 0 {
			size := entry.UsageData.Size
			volume.SizeBytes = &size
			volume.SizeReason = ""
		}
		volumes = append(volumes, volume)
	}
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Name < volumes[j].Name })
	return volumes, nil
}

// containerName takes the first name and trims the leading slash the engine
// attaches to each.
func containerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func skipUntagged(tags []string) []string {
	var result []string
	for _, tag := range tags {
		if tag != "<none>:<none>" && tag != "" {
			result = append(result, tag)
		}
	}
	return result
}

// composeMembership reads the labels Compose marks its containers with.
func composeMembership(labels map[string]string) *ComposeMembership {
	project := labels["com.docker.compose.project"]
	if project == "" {
		return nil
	}
	return &ComposeMembership{
		Project:     project,
		Service:     labels["com.docker.compose.service"],
		ConfigFiles: labels["com.docker.compose.project.config_files"],
		WorkingDir:  labels["com.docker.compose.project.working_dir"],
	}
}

// labelsWithoutSecrets filters out labels whose name suggests a credential.
//
// The engine does not distinguish a plain label from a secret one, so it is
// done by name. Environment variable values are not collected at all - that
// is where passwords go, and the inventory is durable and visible more
// widely than the host itself.
func labelsWithoutSecrets(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		if looksLikeSecret(key) {
			result[key] = "[hidden]"
			continue
		}
		result[key] = value
	}
	return result
}

func looksLikeSecret(key string) bool {
	lowered := strings.ToLower(key)
	for _, pattern := range []string{"secret", "password", "passwd", "token", "apikey", "api_key", "credential"} {
		if strings.Contains(lowered, pattern) {
			return true
		}
	}
	return false
}
