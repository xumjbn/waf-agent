package grpcclient

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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

// nginxStatus 是 nginx stub_status 端点的解析结果。
type nginxStatus struct {
	ActiveConnections int64
	TotalRequests     int64 // 累计已处理请求数（用于算 RPS 速率）
}

// scrapeNginxStatus 拉取并解析 nginx stub_status 输出。典型格式：
//
//	Active connections: 43
//	server accepts handled requests
//	 7368 7368 10993
//	Reading: 0 Writing: 5 Waiting: 38
//
// 第三行第 3 个数字 = 累计请求总数。
func scrapeNginxStatus(url string) (*nginxStatus, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nginx status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	return parseStubStatus(string(body))
}

func parseStubStatus(text string) (*nginxStatus, error) {
	lines := strings.Split(text, "\n")
	var st nginxStatus
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "Active connections:") {
			_, _ = fmt.Sscanf(trimmed, "Active connections: %d", &st.ActiveConnections)
		}
		// 计数行紧跟在 "server accepts handled requests" 之后。
		if strings.Contains(trimmed, "accepts") && strings.Contains(trimmed, "handled") {
			if i+1 < len(lines) {
				fields := strings.Fields(lines[i+1])
				if len(fields) >= 3 {
					_, _ = fmt.Sscanf(fields[2], "%d", &st.TotalRequests)
				}
			}
		}
	}
	return &st, nil
}
