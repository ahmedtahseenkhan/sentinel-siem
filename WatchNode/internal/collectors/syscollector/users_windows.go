//go:build windows

package syscollector

import (
	"bufio"
	"os/exec"
	"strings"
	"time"
)

func (c *Collector) collectUsers(ts time.Time) {
	users := collectWindowsUsers()
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

func collectWindowsUsers() []map[string]string {
	// Use PowerShell Get-LocalUser for reliable output
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-LocalUser | Select-Object Name,Enabled,LastLogon,Description,FullName | ConvertTo-Csv -NoTypeInformation`).Output()
	if err != nil {
		// Fallback to net user
		return collectNetUser()
	}

	var users []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	header := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Skip CSV header
		if header {
			header = false
			continue
		}
		// Parse CSV fields (quoted)
		fields := parseCSVLine(line)
		if len(fields) < 2 {
			continue
		}
		name := unquote(fields[0])
		if name == "" {
			continue
		}
		enabled := strings.EqualFold(unquote(fields[1]), "true")
		lastLogon := ""
		if len(fields) > 2 {
			lastLogon = unquote(fields[2])
		}
		description := ""
		if len(fields) > 3 {
			description = unquote(fields[3])
		}
		fullName := ""
		if len(fields) > 4 {
			fullName = unquote(fields[4])
		}
		enabledStr := "false"
		if enabled {
			enabledStr = "true"
		}
		users = append(users, map[string]string{
			"username":    name,
			"full_name":   fullName,
			"description": description,
			"enabled":     enabledStr,
			"last_logon":  lastLogon,
			"type":        "local",
			"shell":       "cmd.exe",
			"home":        `C:\Users\` + name,
		})
	}
	return users
}

func collectNetUser() []map[string]string {
	out, err := exec.Command("net", "user").Output()
	if err != nil {
		return nil
	}
	var users []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	inList := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "---") {
			inList = true
			continue
		}
		if !inList {
			continue
		}
		if strings.Contains(line, "command completed") {
			break
		}
		// Each line may have up to 3 usernames separated by spaces
		for _, name := range strings.Fields(line) {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			users = append(users, map[string]string{
				"username": name,
				"type":     "local",
				"shell":    "cmd.exe",
			})
		}
	}
	return users
}

func parseCSVLine(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' {
			if inQuote && i+1 < len(line) && line[i+1] == '"' {
				cur.WriteByte('"')
				i++
			} else {
				inQuote = !inQuote
			}
		} else if ch == ',' && !inQuote {
			fields = append(fields, cur.String())
			cur.Reset()
		} else {
			cur.WriteByte(ch)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
