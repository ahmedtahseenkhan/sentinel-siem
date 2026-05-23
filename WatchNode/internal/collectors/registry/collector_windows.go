//go:build windows
// +build windows

package registry

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Maximum subkey depth when Recursive is enabled. Prevents runaway walks
// through HKLM\SOFTWARE or similar trees that contain hundreds of thousands
// of entries.
const maxRecursionDepth = 8

// Start implements models.Collector on Windows.
func (c *Collector) Start(ctx context.Context) error {
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
		c.walk(keyCfg.Path, keyCfg.Recursive, 0, func(path string) {
			c.baseline[path] = c.readValues(path)
		})
	}
}

func (c *Collector) scanChanges() {
	ts := time.Now()
	seen := make(map[string]struct{})

	for _, keyCfg := range c.cfg.Keys {
		c.walk(keyCfg.Path, keyCfg.Recursive, 0, func(path string) {
			seen[path] = struct{}{}
			c.checkKey(ts, path)
		})
	}

	// Detect keys that existed in baseline but are no longer reachable
	// (whole-key deletion within a recursive root).
	for path := range c.baseline {
		if _, ok := seen[path]; ok {
			continue
		}
		if !c.pathCoveredByConfig(path) {
			continue
		}
		c.emit(ts, "registry.deleted", map[string]interface{}{
			"key":     path,
			"message": fmt.Sprintf("Registry key deleted: %s", path),
		}, map[string]string{"key": path})
		delete(c.baseline, path)
	}
}

// walk visits a key and, if recursive, its subkeys up to maxRecursionDepth.
// visit is called once per existing key path.
func (c *Collector) walk(keyPath string, recursive bool, depth int, visit func(string)) {
	root, subKey := splitKeyPath(keyPath)
	k, err := registry.OpenKey(root, subKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	visit(keyPath)

	if !recursive || depth >= maxRecursionDepth {
		k.Close()
		return
	}
	subs, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return
	}
	for _, sub := range subs {
		c.walk(keyPath+`\`+sub, true, depth+1, visit)
	}
}

// pathCoveredByConfig returns true if path is under any configured recursive
// root, used to scope the deletion sweep.
func (c *Collector) pathCoveredByConfig(path string) bool {
	for _, keyCfg := range c.cfg.Keys {
		if path == keyCfg.Path {
			return true
		}
		if keyCfg.Recursive && strings.HasPrefix(path, keyCfg.Path+`\`) {
			return true
		}
	}
	return false
}

// readValues returns every value under keyPath as name -> stringified data.
// Supports REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ.
// Previously only REG_SZ values were captured, silently missing the majority
// of ASEP/persistence registry data.
func (c *Collector) readValues(keyPath string) map[string]string {
	out := make(map[string]string)
	root, subKey := splitKeyPath(keyPath)
	k, err := registry.OpenKey(root, subKey, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return out
	}
	for _, name := range names {
		out[name] = readTypedValue(k, name)
	}
	return out
}

// readTypedValue dispatches on the value's actual REG_* type and returns a
// stringified form suitable for diff. Binary blobs are hex-encoded and
// truncated to 256 bytes (512 hex chars) so large BLOBs do not blow up
// memory or transport.
func readTypedValue(k registry.Key, name string) string {
	// Type discovery: GetValue with a nil buffer returns the value type
	// in valtype even when it fails with ErrShortBuffer.
	_, valtype, err := k.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		// Empty values still report a type; only bail on real errors.
		if valtype == 0 {
			return ""
		}
	}

	switch valtype {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return ""
		}
		return s
	case registry.DWORD, registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return ""
		}
		return strconv.FormatUint(n, 10)
	case registry.BINARY:
		b, _, err := k.GetBinaryValue(name)
		if err != nil {
			return ""
		}
		if len(b) > 256 {
			b = b[:256]
		}
		return hex.EncodeToString(b)
	case registry.MULTI_SZ:
		ss, _, err := k.GetStringsValue(name)
		if err != nil {
			return ""
		}
		return strings.Join(ss, "\x00")
	default:
		return ""
	}
}

func (c *Collector) checkKey(ts time.Time, keyPath string) {
	currentVals := c.readValues(keyPath)
	oldVals := c.baseline[keyPath]
	if oldVals == nil {
		// First time we see this key — treat as baseline, not change.
		c.baseline[keyPath] = currentVals
		return
	}

	for name, val := range currentVals {
		oldVal, existed := oldVals[name]
		if !existed {
			c.emit(ts, "registry.value_added", map[string]interface{}{
				"key":        keyPath,
				"value_name": name,
				"new_data":   val,
				"message":    fmt.Sprintf("Registry value added: %s\\%s", keyPath, name),
			}, map[string]string{"key": keyPath, "value_name": name})
		} else if oldVal != val {
			c.emit(ts, "registry.value_modified", map[string]interface{}{
				"key":        keyPath,
				"value_name": name,
				"old_data":   oldVal,
				"new_data":   val,
				"message":    fmt.Sprintf("Registry value modified: %s\\%s", keyPath, name),
			}, map[string]string{"key": keyPath, "value_name": name})
		}
	}

	for name := range oldVals {
		if _, exists := currentVals[name]; !exists {
			c.emit(ts, "registry.value_deleted", map[string]interface{}{
				"key":        keyPath,
				"value_name": name,
				"old_data":   oldVals[name],
				"message":    fmt.Sprintf("Registry value deleted: %s\\%s", keyPath, name),
			}, map[string]string{"key": keyPath, "value_name": name})
		}
	}

	c.baseline[keyPath] = currentVals
}

func splitKeyPath(path string) (registry.Key, string) {
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
