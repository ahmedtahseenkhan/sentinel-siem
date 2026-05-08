//go:build windows
// +build windows

package registry

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Start implements models.Collector on Windows.
func (c *Collector) Start(ctx context.Context) error {
	// Build initial baseline
	c.buildBaseline()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.scanChanges()
		}
	}
}

func (c *Collector) buildBaseline() {
	for _, keyCfg := range c.cfg.Keys {
		c.readKey(keyCfg.Path)
	}
}

func (c *Collector) scanChanges() {
	ts := time.Now()
	for _, keyCfg := range c.cfg.Keys {
		c.checkKey(ts, keyCfg.Path)
	}
}

func (c *Collector) readKey(keyPath string) {
	root, subKey := splitKeyPath(keyPath)
	k, err := registry.OpenKey(root, subKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	vals := make(map[string]string)
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err == nil {
			vals[name] = val
		}
	}
	c.baseline[keyPath] = vals
}

func (c *Collector) checkKey(ts time.Time, keyPath string) {
	root, subKey := splitKeyPath(keyPath)
	k, err := registry.OpenKey(root, subKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		// Key may have been deleted
		if _, ok := c.baseline[keyPath]; ok {
			c.emit(ts, "registry.deleted", map[string]interface{}{
				"key":     keyPath,
				"message": fmt.Sprintf("Registry key deleted: %s", keyPath),
			}, map[string]string{"key": keyPath})
			delete(c.baseline, keyPath)
		}
		return
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}

	currentVals := make(map[string]string)
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err == nil {
			currentVals[name] = val
		}
	}

	oldVals := c.baseline[keyPath]
	if oldVals == nil {
		oldVals = make(map[string]string)
	}

	// Check modified/new values
	for name, val := range currentVals {
		oldVal, existed := oldVals[name]
		if !existed {
			c.emit(ts, "registry.value_added", map[string]interface{}{
				"key":       keyPath,
				"value_name": name,
				"new_data":   val,
				"message":   fmt.Sprintf("Registry value added: %s\\%s", keyPath, name),
			}, map[string]string{"key": keyPath, "value_name": name})
		} else if oldVal != val {
			c.emit(ts, "registry.value_modified", map[string]interface{}{
				"key":         keyPath,
				"value_name":   name,
				"old_data":     oldVal,
				"new_data":     val,
				"message":     fmt.Sprintf("Registry value modified: %s\\%s", keyPath, name),
			}, map[string]string{"key": keyPath, "value_name": name})
		}
	}

	// Check deleted values
	for name := range oldVals {
		if _, exists := currentVals[name]; !exists {
			c.emit(ts, "registry.value_deleted", map[string]interface{}{
				"key":       keyPath,
				"value_name": name,
				"message":   fmt.Sprintf("Registry value deleted: %s\\%s", keyPath, name),
			}, map[string]string{"key": keyPath, "value_name": name})
		}
	}

	c.baseline[keyPath] = currentVals
}

func splitKeyPath(path string) (registry.Key, string) {
	// Expected format: HKEY_LOCAL_MACHINE\SOFTWARE\...
	parts := splitFirst(path, '\\')
	rootStr := parts[0]
	subKey := ""
	if len(parts) > 1 {
		subKey = parts[1]
	}
	switch rootStr {
	case "HKEY_LOCAL_MACHINE", "HKLM":
		return registry.LOCAL_MACHINE, subKey
	case "HKEY_CURRENT_USER", "HKCU":
		return registry.CURRENT_USER, subKey
	case "HKEY_CLASSES_ROOT", "HKCR":
		return registry.CLASSES_ROOT, subKey
	case "HKEY_USERS", "HKU":
		return registry.USERS, subKey
	default:
		return registry.LOCAL_MACHINE, path
	}
}

func splitFirst(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
