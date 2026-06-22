package web

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/model"

	"github.com/darkace1998/FlowLens/internal/util"
)

// --- Template helpers ---

var funcMap = template.FuncMap{
	"formatBytes":    util.FormatBytes,
	"formatPkts":     util.FormatCount,
	"formatBPS":      formatBPS,
	"formatPPS":      formatPPS,
	"formatDuration": model.FormatDurationShort,
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
	"int": func(v interface{}) int {
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

func formatBPS(bytesTotal uint64, duration time.Duration) string {
	if duration == 0 {
		return "0.00 bps"
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
	case bps > 0:
		// Positive rates below 1 Kbps.
		return fmt.Sprintf("%.2f bps", bps)
	default:
		return "0.00 bps"
	}
}

func formatPPS(pktsTotal uint64, duration time.Duration) string {
	if duration == 0 {
		return "0.00 pps"
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
	case pps > 0:
		// Positive rates below 1 Kpps.
		return fmt.Sprintf("%.2f pps", pps)
	default:
		return "0.00 pps"
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
	case bps > 0:
		// Positive rates below 1 Kbps.
		return fmt.Sprintf("%.2f bps", bps)
	default:
		return "0.00 bps"
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

// formatIPv6FlowLabel returns a formatted IPv6 flow label string or "—" if zero.
func formatIPv6FlowLabel(label uint32) string {
	if label == 0 {
		return "—"
	}
	return fmt.Sprintf("0x%08X", label)
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
	v := math.Round(float64(part)/float64(total)*1000) / 10
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

// sortByBytes sorts a slice of any type in descending order based on the bytes retrieved by getBytes.
func sortByBytes[T any](slice []T, getBytes func(T) uint64) {
	sort.Slice(slice, func(i, j int) bool {
		return getBytes(slice[i]) > getBytes(slice[j])
	})
}
