//go:build !windows

package syscollector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

func (c *Collector) collectUsers(ts time.Time) {
	users := collectPasswd()
	for _, u := range users {
		fields := map[string]interface{}{}
		for k, v := range u {
			fields[k] = v
		}
		c.emit(ts, "syscollector.users", fields, map[string]string{
			"username": u["username"],
		})
	}
}

func collectPasswd() []map[string]string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	var users []map[string]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		// username:password:uid:gid:comment:home:shell
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		comment := parts[4]
		home := parts[5]
		shell := parts[6]

		// Skip system accounts (uid < 1000 on Linux, uid < 500 on macOS)
		// but always include root for visibility
		if uid != 0 && uid < 500 {
			continue
		}
		// Skip no-login shells
		if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") || strings.Contains(shell, "sync") {
			continue
		}

		users = append(users, map[string]string{
			"username": username,
			"uid":      strconv.Itoa(uid),
			"gid":      strconv.Itoa(gid),
			"comment":  comment,
			"home":     home,
			"shell":    shell,
			"type":     userType(uid),
		})
	}
	return users
}

func userType(uid int) string {
	if uid == 0 {
		return "root"
	}
	if uid >= 1000 {
		return "local"
	}
	return "system"
}
