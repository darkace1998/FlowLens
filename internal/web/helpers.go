package web

import (
	"fmt"
	"html/template"
	"math"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/model"
)

// --- Template helpers ---

var funcMap = template.FuncMap{
	"formatBytes":    formatBytes,
	"formatPkts":     formatPkts,
	"formatBPS":      formatBPS,
	"formatPPS":      formatPPS,
	"formatDuration": formatDuration,
	"protoName":      model.ProtocolName,
	"appProto":       model.AppProtocol,
	"appCategory":    model.AppCategory,
	"asName":         model.ASName,
	"timeAgo":        timeAgo,
	"formatTime":     formatTime,
	"seq":            seq,
	"pageWindow":     pageWindow,
	"add":            func(a, b int) int { return a + b },
	"sub":            func(a, b int) int { return a - b },
	"pctOf":          pctOf,
	"severityClass":  severityClass,
	"formatAS":       formatAS,
	"formatJitter":   formatJitter,
	"formatMOS":      formatMOS,
	"int":           func(v interface{}) int {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case uint64:
			return int(n)
		case float64:
			return int(n)
		default:
			return 0
		}
	},
	"uint64": func(v interface{}) uint64 {
		switch n := v.(type) {
		case int:
			return uint64(n)
		case int64:
			return uint64(n)
		case uint64:
			return n
		case float64:
			return uint64(n)
		default:
			return 0
		}
	},
	"gt": func(a, b int) bool { return a > b },
}

func severityClass(sev analysis.Severity) string {
	switch sev {
	case analysis.CRITICAL:
		return "critical"
	case analysis.WARNING:
		return "warning"
	default:
		return "info"
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatPkts(p uint64) string {
	switch {
	case p < 1000:
		return fmt.Sprintf("%d", p)
	case p < 1_000_000:
		return fmt.Sprintf("%.1fK", float64(p)/1e3)
	case p < 1_000_000_000:
		return fmt.Sprintf("%.1fM", float64(p)/1e6)
	case p < 1_000_000_000_000:
		return fmt.Sprintf("%.1fB", float64(p)/1e9)
	default:
		return fmt.Sprintf("%.1fT", float64(p)/1e12)
	}
}

func formatBPS(bytesTotal uint64, duration time.Duration) string {
	if duration == 0 {
		return "0 bps"
	}
	bps := float64(bytesTotal) * 8 / duration.Seconds()
	switch {
	case bps >= 1e18:
		return fmt.Sprintf("%.2f Ebps", bps/1e18)
	case bps >= 1e15:
		return fmt.Sprintf("%.2f Pbps", bps/1e15)
	case bps >= 1e12:
		return fmt.Sprintf("%.2f Tbps", bps/1e12)
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func formatPPS(pktsTotal uint64, duration time.Duration) string {
	if duration == 0 {
		return "0 pps"
	}
	pps := float64(pktsTotal) / duration.Seconds()
	switch {
	case pps >= 1e12:
		return fmt.Sprintf("%.2f Tpps", pps/1e12)
	case pps >= 1e9:
		return fmt.Sprintf("%.2f Gpps", pps/1e9)
	case pps >= 1e6:
		return fmt.Sprintf("%.2f Mpps", pps/1e6)
	case pps >= 1e3:
		return fmt.Sprintf("%.2f Kpps", pps/1e3)
	case pps >= 1:
		return fmt.Sprintf("%.0f pps", pps)
	case pps > 0:
		// Small positive rates (e.g. 152 pkts / 10 min = 0.25 pps).
		// Avoid rounding to "0 pps" which is misleading when there is clearly traffic.
		return fmt.Sprintf("%.2f pps", pps)
	default:
		return "0 pps"
	}
}

func formatThroughput(bps float64) string {
	if bps <= 0 {
		return "—"
	}
	switch {
	case bps >= 1e18:
		return fmt.Sprintf("%.2f Ebps", bps/1e18)
	case bps >= 1e15:
		return fmt.Sprintf("%.2f Pbps", bps/1e15)
	case bps >= 1e12:
		return fmt.Sprintf("%.2f Tbps", bps/1e12)
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func formatRTT(us int64) string {
	if us <= 0 {
		return "—"
	}
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	}
	ms := float64(us) / 1000
	if ms < 1000 {
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.2fs", ms/1000)
}

func formatJitter(us int64) string {
	if us <= 0 {
		return "—"
	}
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	}
	return fmt.Sprintf("%.1fms", float64(us)/1000)
}

func formatMOS(mos float32) string {
	if mos <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f", mos)
}

func mosQuality(mos float32) string {
	switch {
	case mos >= 4.0:
		return "good"
	case mos >= 3.5:
		return "fair"
	case mos >= 3.0:
		return "poor"
	default:
		return "bad"
	}
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// formatDuration returns a human-friendly duration string (e.g. "10m" instead of "10m0s").
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}
	totalSecs := int(d.Seconds())
	h := totalSecs / 3600
	m := (totalSecs % 3600) / 60
	s := totalSecs % 60
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

func seq(start, end int) []int {
	s := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		s = append(s, i)
	}
	return s
}

// pageWindow returns a sliding window of page numbers around the current page,
// showing at most 5 pages centered on the current page.
func pageWindow(currentPage, totalPages int) []int {
	const windowSize = 5
	start := currentPage - windowSize/2
	end := start + windowSize - 1

	if start < 1 {
		start = 1
		end = start + windowSize - 1
	}
	if end > totalPages {
		end = totalPages
		start = end - windowSize + 1
		if start < 1 {
			start = 1
		}
	}

	pages := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}
	return pages
}

func pctOf(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	v := math.Round(float64(part) / float64(total) * 1000) / 10
	if v > 100 {
		v = 100
	}
	return v
}

func formatAS(asn uint32) string {
	name := model.ASName(asn)
	if asn == 0 {
		return name
	}
	return fmt.Sprintf("AS%d (%s)", asn, name)
}
