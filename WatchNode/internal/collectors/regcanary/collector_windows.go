//go:build windows
// +build windows

package regcanary

import (
	"context"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Start plants the decoys, then polls them for modification/deletion.
func (c *Collector) Start(ctx context.Context) error {
	c.plantAll()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.check()
		}
	}
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) plantAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, keyPath := range c.keys() {
		root, sub := splitKeyPath(keyPath)
		k, err := registry.OpenKey(root, sub, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			k, _, err = registry.CreateKey(root, sub, registry.SET_VALUE|registry.QUERY_VALUE)
			if err != nil {
				continue
			}
		}
		for name, data := range decoyValues {
			if err := k.SetStringValue(name, data); err == nil {
				c.planted[keyPath+"|"+name] = data
			}
		}
		k.Close()
	}
}

func (c *Collector) check() {
	c.mu.Lock()
	snapshot := make(map[string]string, len(c.planted))
	for id, data := range c.planted {
		snapshot[id] = data
	}
	c.mu.Unlock()

	for id, expected := range snapshot {
		keyPath, name := splitID(id)
		root, sub := splitKeyPath(keyPath)
		k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE)
		if err != nil {
			c.tamper(keyPath, name, "key-deleted")
			c.replant(keyPath, name)
			continue
		}
		cur, _, err := k.GetStringValue(name)
		k.Close()
		if err != nil {
			c.tamper(keyPath, name, "deleted")
			c.replant(keyPath, name)
			continue
		}
		if cur != expected {
			c.tamper(keyPath, name, "modified")
			c.replant(keyPath, name)
		}
	}
}

// replant restores a tampered decoy so it keeps tripping, and refreshes the
// baseline so the agent's own re-write isn't a false hit.
func (c *Collector) replant(keyPath, name string) {
	data, ok := decoyValues[name]
	if !ok {
		return
	}
	root, sub := splitKeyPath(keyPath)
	k, err := registry.OpenKey(root, sub, registry.SET_VALUE)
	if err != nil {
		k, _, err = registry.CreateKey(root, sub, registry.SET_VALUE)
		if err != nil {
			return
		}
	}
	_ = k.SetStringValue(name, data)
	k.Close()
	c.mu.Lock()
	c.planted[keyPath+"|"+name] = data
	c.mu.Unlock()
}

func splitID(id string) (string, string) {
	if i := strings.LastIndex(id, "|"); i >= 0 {
		return id[:i], id[i+1:]
	}
	return id, ""
}

func splitKeyPath(path string) (registry.Key, string) {
	root := path
	sub := ""
	if i := strings.IndexByte(path, '\\'); i >= 0 {
		root = path[:i]
		sub = path[i+1:]
	}
	switch root {
	case "HKEY_LOCAL_MACHINE", "HKLM":
		return registry.LOCAL_MACHINE, sub
	case "HKEY_CURRENT_USER", "HKCU":
		return registry.CURRENT_USER, sub
	case "HKEY_CLASSES_ROOT", "HKCR":
		return registry.CLASSES_ROOT, sub
	case "HKEY_USERS", "HKU":
		return registry.USERS, sub
	default:
		return registry.LOCAL_MACHINE, path
	}
}
