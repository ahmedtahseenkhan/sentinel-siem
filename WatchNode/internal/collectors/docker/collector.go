package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "docker"

// Container represents a Docker container from the API.
type Container struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Command string            `json:"Command"`
	Created int64             `json:"Created"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Ports   []ContainerPort   `json:"Ports"`
	Labels  map[string]string `json:"Labels"`
}

// ContainerPort is a Docker port mapping.
type ContainerPort struct {
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort,omitempty"`
	Type        string `json:"Type"`
}

// DockerEvent is a Docker daemon event.
type DockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

// Collector monitors Docker containers and events.
type Collector struct {
	cfg      agent.DockerCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	client   *http.Client
	wg       sync.WaitGroup
}

// New creates a Docker security collector.
func New(cfg agent.DockerCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 60*time.Second)
	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 256),
		stopCh:   make(chan struct{}),
		client:   &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Start(ctx context.Context) error {
	// Start event listener
	c.wg.Add(1)
	go c.listenEvents(ctx)

	// Periodic inventory
	c.collectContainers()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.collectContainers()
		}
	}
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}

func (c *Collector) collectContainers() {
	resp, err := c.client.Get("http://localhost/v1.43/containers/json?all=true")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return
	}

	ts := time.Now()
	for _, container := range containers {
		name := ""
		if len(container.Names) > 0 {
			name = container.Names[0]
		}
		c.emit(ts, "docker.container", map[string]interface{}{
			"container_id":   container.ID[:12],
			"name":           name,
			"image":          container.Image,
			"state":          container.State,
			"status":         container.Status,
			"command":        container.Command,
			"created":        container.Created,
		}, map[string]string{
			"container_id": container.ID[:12],
			"state":        container.State,
		})
	}

	// Summary
	running, stopped, total := 0, 0, len(containers)
	for _, ct := range containers {
		if ct.State == "running" {
			running++
		} else {
			stopped++
		}
	}
	c.emit(ts, "docker.summary", map[string]interface{}{
		"total":   total,
		"running": running,
		"stopped": stopped,
	}, nil)
}

func (c *Collector) listenEvents(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
			c.streamEvents(ctx)
			// Reconnect after delay
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			}
		}
	}
}

func (c *Collector) streamEvents(ctx context.Context) {
	streamClient := &http.Client{
		Transport: c.client.Transport,
		// No timeout for streaming
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/v1.43/events", nil)
	if err != nil {
		return
	}
	resp, err := streamClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	for {
		var event DockerEvent
		if err := dec.Decode(&event); err != nil {
			return
		}
		ts := time.Unix(event.Time, 0)
		containerName := event.Actor.Attributes["name"]
		image := event.Actor.Attributes["image"]
		c.emit(ts, "docker.event", map[string]interface{}{
			"type":           event.Type,
			"action":         event.Action,
			"container_id":   event.Actor.ID,
			"container_name": containerName,
			"image":          image,
			"message":        fmt.Sprintf("Docker %s: %s on %s (%s)", event.Type, event.Action, containerName, image),
		}, map[string]string{
			"type":   event.Type,
			"action": event.Action,
		})
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
