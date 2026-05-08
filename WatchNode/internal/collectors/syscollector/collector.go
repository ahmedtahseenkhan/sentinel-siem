package syscollector

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "syscollector"

// Collector gathers comprehensive host asset inventory.
type Collector struct {
	cfg      agent.SyscollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates a syscollector.
func New(cfg agent.SyscollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 1*time.Hour)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 512),
		stopCh:   make(chan struct{}),
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Start(ctx context.Context) error {
	c.collect()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) collect() {
	ts := time.Now()
	if c.cfg.Hardware {
		c.collectHardware(ts)
	}
	if c.cfg.OS {
		c.collectOS(ts)
	}
	if c.cfg.Packages {
		c.collectPackages(ts)
	}
	if c.cfg.Ports {
		c.collectPorts(ts)
	}
	if c.cfg.NetIfaces {
		c.collectNetworkInterfaces(ts)
	}
	if c.cfg.Users {
		c.collectUsers(ts)
	}
}

func (c *Collector) collectHardware(ts time.Time) {
	fields := map[string]interface{}{
		"cpu_arch":     runtime.GOARCH,
		"num_cpu":      runtime.NumCPU(),
		"go_version":   runtime.Version(),
	}
	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		fields["cpu_model"] = cpuInfo[0].ModelName
		fields["cpu_mhz"] = cpuInfo[0].Mhz
		fields["cpu_cores"] = cpuInfo[0].Cores
		fields["cpu_vendor"] = cpuInfo[0].VendorID
	}
	if v, err := mem.VirtualMemory(); err == nil {
		fields["ram_total"] = v.Total
		fields["ram_free"] = v.Free
		fields["ram_used"] = v.Used
	}
	c.emit(ts, "syscollector.hardware", fields, nil)
}

func (c *Collector) collectOS(ts time.Time) {
	fields := map[string]interface{}{
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}
	if info, err := host.Info(); err == nil {
		fields["hostname"] = info.Hostname
		fields["platform"] = info.Platform
		fields["platform_family"] = info.PlatformFamily
		fields["platform_version"] = info.PlatformVersion
		fields["kernel_version"] = info.KernelVersion
		fields["kernel_arch"] = info.KernelArch
		fields["os_name"] = info.OS
		fields["uptime"] = info.Uptime
		fields["boot_time"] = info.BootTime
	}
	c.emit(ts, "syscollector.os", fields, nil)
}

// platformPackageCollectors holds OS-specific package collectors registered via init().
var platformPackageCollectors []func() []map[string]string

func (c *Collector) collectPackages(ts time.Time) {
	var packages []map[string]string

	// Built-in collectors for Linux and macOS
	switch runtime.GOOS {
	case "linux":
		packages = append(packages, collectDpkg()...)
		packages = append(packages, collectRpm()...)
	case "darwin":
		packages = append(packages, collectBrew()...)
	}

	// Platform-specific collectors registered via init() (e.g. Windows registry)
	for _, fn := range platformPackageCollectors {
		packages = append(packages, fn()...)
	}

	for _, pkg := range packages {
		if pkg["name"] == "" {
			continue
		}
		fields := map[string]interface{}{}
		for k, v := range pkg {
			if v != "" {
				fields[k] = v
			}
		}
		c.emit(ts, "syscollector.packages", fields, map[string]string{
			"package_name": pkg["name"],
		})
	}
}

func collectDpkg() []map[string]string {
	// Try dpkg-query first (full systems), fall back to reading status file directly (containers)
	if out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}|${Version}|${Architecture}|${Maintainer}|${Status}\n").Output(); err == nil {
		var packages []map[string]string
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), "|", 5)
			if len(parts) < 3 {
				continue
			}
			if len(parts) >= 5 && !strings.Contains(parts[4], "installed") {
				continue
			}
			packages = append(packages, map[string]string{
				"name":    strings.TrimSpace(parts[0]),
				"version": strings.TrimSpace(parts[1]),
				"arch":    strings.TrimSpace(parts[2]),
				"vendor":  strings.TrimSpace(parts[3]),
				"format":  "deb",
			})
		}
		return packages
	}
	// Fallback: parse /var/lib/dpkg/status directly (works in distroless containers)
	return collectDpkgStatus()
}

func collectDpkgStatus() []map[string]string {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	defer f.Close()

	var packages []map[string]string
	var cur map[string]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if cur != nil && strings.Contains(cur["status"], "installed") {
				cur["format"] = "deb"
				packages = append(packages, cur)
			}
			cur = nil
			continue
		}
		if cur == nil {
			cur = make(map[string]string)
		}
		if strings.HasPrefix(line, "Package: ") {
			cur["name"] = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			cur["version"] = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Architecture: ") {
			cur["arch"] = strings.TrimPrefix(line, "Architecture: ")
		} else if strings.HasPrefix(line, "Maintainer: ") {
			cur["vendor"] = strings.TrimPrefix(line, "Maintainer: ")
		} else if strings.HasPrefix(line, "Status: ") {
			cur["status"] = strings.TrimPrefix(line, "Status: ")
		}
	}
	return packages
}

func collectRpm() []map[string]string {
	out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{VENDOR}\n").Output()
	if err != nil {
		return nil
	}
	var packages []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "|", 4)
		if len(parts) < 3 {
			continue
		}
		vendor := ""
		if len(parts) == 4 {
			vendor = parts[3]
		}
		packages = append(packages, map[string]string{
			"name":    parts[0],
			"version": parts[1],
			"arch":    parts[2],
			"vendor":  vendor,
			"format":  "rpm",
		})
	}
	return packages
}

func collectBrew() []map[string]string {
	out, err := exec.Command("brew", "list", "--versions").Output()
	if err != nil {
		return nil
	}
	var packages []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		packages = append(packages, map[string]string{
			"name":    parts[0],
			"version": parts[1],
			"format":  "brew",
		})
	}
	return packages
}

func (c *Collector) collectPorts(ts time.Time) {
	conns, err := gnet.Connections("tcp")
	if err != nil {
		return
	}
	seen := make(map[string]bool)
	for _, conn := range conns {
		if conn.Status == "LISTEN" {
			key := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			c.emit(ts, "syscollector.ports", map[string]interface{}{
				"protocol":  "tcp",
				"local_ip":  conn.Laddr.IP,
				"local_port": conn.Laddr.Port,
				"pid":       conn.Pid,
				"state":     conn.Status,
			}, map[string]string{
				"port": fmt.Sprintf("%d", conn.Laddr.Port),
			})
		}
	}
}

func (c *Collector) collectNetworkInterfaces(ts time.Time) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var ipv4, ipv6 []string
		for _, addr := range addrs {
			a := addr.String()
			if strings.Contains(a, ":") {
				ipv6 = append(ipv6, a)
			} else {
				ipv4 = append(ipv4, a)
			}
		}
		c.emit(ts, "syscollector.netif", map[string]interface{}{
			"name":         iface.Name,
			"mac":          iface.HardwareAddr.String(),
			"mtu":          iface.MTU,
			"flags":        iface.Flags.String(),
			"ipv4":         strings.Join(ipv4, ","),
			"ipv6":         strings.Join(ipv6, ","),
		}, map[string]string{
			"interface": iface.Name,
		})
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

// Ensure os import is used.
func init() {
	_ = os.DevNull
}
