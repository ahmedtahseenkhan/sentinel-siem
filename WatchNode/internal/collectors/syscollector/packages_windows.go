//go:build windows

package syscollector

import (
	"golang.org/x/sys/windows/registry"
)

func init() {
	// Register Windows package collector — called by collectPackages()
	platformPackageCollectors = append(platformPackageCollectors, collectWindowsPackages)
}

func collectWindowsPackages() []map[string]string {
	var packages []map[string]string

	// Check both 64-bit and 32-bit uninstall registry hives
	hives := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	seen := make(map[string]bool)
	for _, hive := range hives {
		k, err := registry.OpenKey(hive.root, hive.path, registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, subkey := range subkeys {
			fullPath := hive.path + `\` + subkey
			sk, err := registry.OpenKey(hive.root, fullPath, registry.READ)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			publisher, _, _ := sk.GetStringValue("Publisher")
			installDate, _, _ := sk.GetStringValue("InstallDate")
			installLoc, _, _ := sk.GetStringValue("InstallLocation")
			arch := "x64"
			if hive.path == `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` {
				arch = "x86"
			}
			sk.Close()

			if name == "" {
				continue
			}
			key := name + "|" + version
			if seen[key] {
				continue
			}
			seen[key] = true

			packages = append(packages, map[string]string{
				"name":         name,
				"version":      version,
				"vendor":       publisher,
				"arch":         arch,
				"install_date": installDate,
				"install_loc":  installLoc,
				"format":       "msi",
			})
		}
	}
	return packages
}
