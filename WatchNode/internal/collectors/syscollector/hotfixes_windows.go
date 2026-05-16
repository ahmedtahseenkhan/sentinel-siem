//go:build windows

package syscollector

import (
	"encoding/csv"
	"os/exec"
	"strings"
	"time"
)

func (c *Collector) collectHotfixes(ts time.Time) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-HotFix | Select-Object HotFixID,InstalledOn,Description,InstalledBy | ConvertTo-Csv -NoTypeInformation`,
	).Output()
	if err != nil {
		return
	}

	r := csv.NewReader(strings.NewReader(strings.TrimSpace(string(out))))
	records, err := r.ReadAll()
	if err != nil || len(records) < 2 {
		return
	}

	// records[0] is the header row
	for _, row := range records[1:] {
		if len(row) < 4 {
			continue
		}
		hotfixID := strings.Trim(row[0], `"`)
		installedOn := strings.Trim(row[1], `"`)
		description := strings.Trim(row[2], `"`)
		installedBy := strings.Trim(row[3], `"`)

		if hotfixID == "" {
			continue
		}

		c.emit(ts, "syscollector.hotfixes", map[string]interface{}{
			"hotfix_id":    hotfixID,
			"installed_on": installedOn,
			"description":  description,
			"installed_by": installedBy,
		}, map[string]string{
			"hotfix_id": hotfixID,
		})
	}
}
