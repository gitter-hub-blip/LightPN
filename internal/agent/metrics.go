package agent

import (
	"runtime"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

// collectSys gathers the heartbeat system metrics. Individual collector
// failures degrade to zero values rather than failing the heartbeat.
func collectSys() proto.SysMetrics {
	var m proto.SysMetrics
	if pcts, err := cpu.Percent(0, false); err == nil && len(pcts) > 0 {
		m.CPUPct = pcts[0]
	}
	if avg, err := load.Avg(); err == nil {
		m.Load1 = avg.Load1
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		m.MemUsed = vm.Used
		m.MemTotal = vm.Total
	}
	root := "/"
	if runtime.GOOS == "windows" {
		root = "C:\\"
	}
	if du, err := disk.Usage(root); err == nil {
		m.DiskUsed = du.Used
		m.DiskTotal = du.Total
	}
	if counters, err := psnet.IOCounters(false); err == nil && len(counters) > 0 {
		m.NetRx = counters[0].BytesRecv
		m.NetTx = counters[0].BytesSent
	}
	if up, err := host.Uptime(); err == nil {
		m.UptimeS = up
	}
	return m
}

// warmupCPU primes the cpu.Percent delta baseline so the first heartbeat
// carries a real value.
func warmupCPU() {
	cpu.Percent(0, false)
	time.Sleep(100 * time.Millisecond)
}
