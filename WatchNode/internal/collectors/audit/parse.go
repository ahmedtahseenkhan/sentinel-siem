package audit

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// record groups one logical auditd event. auditd splits a single event
// across several log lines that share the same msg=audit(TS:ID) header.
type record struct {
	id        string
	tsEpoch   float64
	types     string
	fields    map[string]interface{}
	lastTouch time.Time
}

func (r *record) firstNonEmpty(keys ...string) string {
	for _, k := range keys {
		if v, ok := r.fields[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (r *record) resolveUserName(uid string) string {
	if uid == "" || uid == "-1" || uid == "4294967295" {
		return ""
	}
	// Best-effort: read /etc/passwd line for the uid. We avoid the os/user
	// package because it can shell out to NSS (slow + extra syscalls).
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return uid
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[2] == uid {
			return parts[0]
		}
	}
	return uid
}

func (r *record) timestamp() time.Time {
	if r.tsEpoch == 0 {
		return time.Now()
	}
	sec := int64(r.tsEpoch)
	nsec := int64((r.tsEpoch - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}

type grouper struct {
	cur *record
}

func newGrouper() *grouper { return &grouper{} }

// feed processes one audit.log line. Returns a completed record when the line
// belongs to a different msg ID than what we were accumulating (the previous
// record is flushed); otherwise returns nil.
func (g *grouper) feed(line string) *record {
	t, id, ts := parseMsgHeader(line)
	if t == "" {
		return nil
	}

	if g.cur == nil {
		g.cur = &record{id: id, tsEpoch: ts, types: t, fields: map[string]interface{}{}, lastTouch: time.Now()}
	} else if g.cur.id != id {
		out := g.cur
		g.cur = &record{id: id, tsEpoch: ts, types: t, fields: map[string]interface{}{}, lastTouch: time.Now()}
		mergeKVs(g.cur.fields, t, line)
		return out
	} else {
		g.cur.types = g.cur.types + "," + t
		g.cur.lastTouch = time.Now()
	}
	mergeKVs(g.cur.fields, t, line)
	return nil
}

// flushIdle returns the current record if it has been idle for at least idle
// duration, ensuring trailing records emit even when no new line arrives.
func (g *grouper) flushIdle(idle time.Duration) *record {
	if g.cur != nil && time.Since(g.cur.lastTouch) >= idle {
		out := g.cur
		g.cur = nil
		return out
	}
	return nil
}

// parseMsgHeader extracts (type, id, epochSeconds) from
//
//	type=XYZ msg=audit(1700000000.123:42): k1=v1 k2="v2"
//
// Returns ("", "", 0) if line is not a recognizable audit message.
func parseMsgHeader(line string) (string, string, float64) {
	if !strings.HasPrefix(line, "type=") {
		return "", "", 0
	}
	rest := line[len("type="):]
	sp := strings.IndexByte(rest, ' ')
	if sp == -1 {
		return "", "", 0
	}
	typ := rest[:sp]
	rest = rest[sp+1:]

	if !strings.HasPrefix(rest, "msg=audit(") {
		return typ, "", 0
	}
	rest = rest[len("msg=audit("):]
	end := strings.Index(rest, "):")
	if end == -1 {
		return typ, "", 0
	}
	hdr := rest[:end]
	colon := strings.IndexByte(hdr, ':')
	if colon == -1 {
		return typ, "", 0
	}
	tsStr := hdr[:colon]
	id := hdr[colon+1:]

	var ts float64
	_, _ = fmt.Sscanf(tsStr, "%f", &ts)
	return typ, id, ts
}

// mergeKVs scans key=value pairs after the msg=audit(...) header into fields.
// Values may be bare (cwd=/var/log), quoted (comm="bash"), or hex-encoded
// (name=2F65... for paths containing spaces).
func mergeKVs(fields map[string]interface{}, recType, line string) {
	colon := strings.Index(line, "):")
	if colon == -1 {
		return
	}
	rest := strings.TrimLeft(line[colon+2:], " ")

	for len(rest) > 0 {
		eq := strings.IndexByte(rest, '=')
		if eq == -1 {
			break
		}
		key := rest[:eq]
		rest = rest[eq+1:]

		var val string
		switch {
		case len(rest) > 0 && rest[0] == '"':
			end := strings.IndexByte(rest[1:], '"')
			if end == -1 {
				val = rest[1:]
				rest = ""
			} else {
				val = rest[1 : 1+end]
				rest = rest[1+end+1:]
			}
		default:
			sp := strings.IndexByte(rest, ' ')
			if sp == -1 {
				val = rest
				rest = ""
			} else {
				val = rest[:sp]
				rest = rest[sp+1:]
			}
			if (key == "name" || key == "proctitle" || key == "exe") &&
				isHex(val) && len(val)%2 == 0 {
				if b, err := hex.DecodeString(val); err == nil {
					val = string(b)
				}
			}
		}
		rest = strings.TrimLeft(rest, " ")
		fields[key] = val
		fields["_type"] = recType
	}
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
