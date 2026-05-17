package grpcclient

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"

	pb "github.com/waf-control/proto/agent"
)

func collectMetrics() *pb.ResourceUsage {
	var r pb.ResourceUsage

	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		r.CpuPercent = pct[0]
	}

	if m, err := mem.VirtualMemory(); err == nil {
		r.MemoryPercent = m.UsedPercent
		r.MemoryUsedBytes = int64(m.Used)
	}

	if d, err := disk.Usage("/"); err == nil {
		r.DiskPercent = d.UsedPercent
		r.DiskUsedBytes = int64(d.Used)
	}

	return &r
}
