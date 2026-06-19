package web

import (
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatPkts(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.0K"},
		{500000, "500.0K"},
		{1000000, "1.0M"},
		{999999999, "1000.0M"},
		{1000000000, "1.0B"},
		{5500000000, "5.5B"},
		{1000000000000, "1.0T"},
		{86805636224700000, "86805.6T"},
	}
	for _, tt := range tests {
		got := formatPkts(tt.input)
		if got != tt.want {
			t.Errorf("formatPkts(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatBPS(t *testing.T) {
	tests := []struct {
		bytesTotal uint64
		duration   time.Duration
		want       string
		contains   bool
	}{
		{0, 10 * time.Second, "0.00 bps", false},
		{100, 0, "0.00 bps", false},
		{1, 10 * time.Second, "0.80 bps", false},    // Test small BPS (bug #8-like)
		{100, 10 * time.Second, "80.00 bps", false}, // Test bps >= 1 but < 1000
		{1250, 10 * time.Second, "1.00 Kbps", false},
		{1_250_000, 10 * time.Second, "1.00 Mbps", false},
		{1_250_000_000, 10 * time.Second, "1.00 Gbps", false},
		{1_250_000_000_000, 10 * time.Second, "1.00 Tbps", false},
		{1_250_000_000_000_000, 10 * time.Second, "1.00 Pbps", false},
		{1_250_000_000_000_000_000, 10 * time.Second, "1.00 Ebps", false},
		{1000000, 10 * time.Minute, "Kbps", true},                   // Original explicit test
		{3_000_000_000_000_000_000, 10 * time.Minute, "Pbps", true}, // Large byte values that would overflow if computed as uint64(bytes*8). 3 EB * 8 = 24e18 which exceeds uint64 max (~18.4e18).
	}
	for _, tt := range tests {
		got := formatBPS(tt.bytesTotal, tt.duration)
		if tt.contains {
			if !strings.Contains(got, tt.want) {
				t.Errorf("formatBPS(%d, %v) = %q, want it to contain %q", tt.bytesTotal, tt.duration, got, tt.want)
			}
		} else {
			if got != tt.want {
				t.Errorf("formatBPS(%d, %v) = %q, want %q", tt.bytesTotal, tt.duration, got, tt.want)
			}
		}
	}
}

func TestFormatPPS(t *testing.T) {
	tests := []struct {
		pkts     uint64
		duration time.Duration
		want     string
	}{
		{0, 10 * time.Minute, "0.00 pps"},
		{1000, 0, "0.00 pps"},
		{152, 10 * time.Minute, "0.25 pps"}, // verified fix for bug #8: small pps should not round to 0 pps incorrectly
		{30, 1 * time.Minute, "0.50 pps"},
		{1, 1 * time.Second, "1.00 pps"},
		{6000, 10 * time.Second, "600.00 pps"},
		{60000, 10 * time.Second, "6.00 Kpps"},
		{60000000, 10 * time.Second, "6.00 Mpps"},
		{60000000000, 10 * time.Second, "6.00 Gpps"},
		{60000000000000, 10 * time.Second, "6.00 Tpps"},
	}
	for _, tt := range tests {
		got := formatPPS(tt.pkts, tt.duration)
		if got != tt.want {
			t.Errorf("formatPPS(%d, %v) = %q, want %q", tt.pkts, tt.duration, got, tt.want)
		}
	}
}

func TestFormatThroughput(t *testing.T) {
	tests := []struct {
		bps  float64
		want string
	}{
		{0, "—"},
		{0.25, "0.25 bps"},
		{500, "500.00 bps"},
		{5000, "5.00 Kbps"},
		{5000000, "5.00 Mbps"},
		{5000000000, "5.00 Gbps"},
		{5e12, "5.00 Tbps"},
		{5e15, "5.00 Pbps"},
		{5e18, "5.00 Ebps"},
	}
	for _, tt := range tests {
		got := formatThroughput(tt.bps)
		if got != tt.want {
			t.Errorf("formatThroughput(%f) = %q, want %q", tt.bps, got, tt.want)
		}
	}
}

func TestFormatRTT(t *testing.T) {
	tests := []struct {
		us   int64
		want string
	}{
		{0, "—"},
		{500, "500µs"},
		{1500, "1.5ms"},
		{150000, "150.0ms"},
		{1500000, "1.50s"},
	}
	for _, tt := range tests {
		got := formatRTT(tt.us)
		if got != tt.want {
			t.Errorf("formatRTT(%d) = %q, want %q", tt.us, got, tt.want)
		}
	}
}

func TestFormatJitter(t *testing.T) {
	tests := []struct {
		us   int64
		want string
	}{
		{0, "—"},
		{500, "500µs"},
		{5000, "5.0ms"},
		{100000, "100.0ms"},
	}
	for _, tt := range tests {
		got := formatJitter(tt.us)
		if got != tt.want {
			t.Errorf("formatJitter(%d) = %q, want %q", tt.us, got, tt.want)
		}
	}
}

func TestFormatMOS(t *testing.T) {
	tests := []struct {
		mos  float32
		want string
	}{
		{0, "—"},
		{-1.0, "—"},
		{4.41, "4.41"},
		{3.50, "3.50"},
		{2.10, "2.10"},
		{4.414, "4.41"},
		{4.415, "4.41"}, // float32 rounding behavior with fmt.Sprintf("%.2f")
		{5.0, "5.00"},
	}
	for _, tt := range tests {
		got := formatMOS(tt.mos)
		if got != tt.want {
			t.Errorf("formatMOS(%.3f) = %q, want %q", tt.mos, got, tt.want)
		}
	}
}

func TestMOSQuality(t *testing.T) {
	tests := []struct {
		mos  float32
		want string
	}{
		{4.2, "good"},
		{4.0, "good"},
		{3.99, "fair"},
		{3.7, "fair"},
		{3.5, "fair"},
		{3.49, "poor"},
		{3.2, "poor"},
		{3.0, "poor"},
		{2.99, "bad"},
		{2.5, "bad"},
		{0, "bad"},
	}
	for _, tt := range tests {
		got := mosQuality(tt.mos)
		if got != tt.want {
			t.Errorf("mosQuality(%.2f) = %q, want %q", tt.mos, got, tt.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{500 * time.Millisecond, "500ms"},
		{10 * time.Minute, "10m"},
		{1 * time.Hour, "1h"},
		{90 * time.Minute, "1h 30m"},
		{30 * time.Second, "30s"},
		{5*time.Minute + 30*time.Second, "5m 30s"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.input)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPctOf(t *testing.T) {
	tests := []struct {
		part, total uint64
		want        float64
	}{
		{0, 0, 0},
		{50, 100, 50},
		{100, 100, 100},
		{200, 100, 100}, // capped at 100
		{101, 100, 100}, // minimal overflow capped at 100
		{1, 3, 33.3},
	}
	for _, tt := range tests {
		got := pctOf(tt.part, tt.total)
		if got != tt.want {
			t.Errorf("pctOf(%d, %d) = %v, want %v", tt.part, tt.total, got, tt.want)
		}
	}
}

func TestPercentileInt64(t *testing.T) {
	sorted := []int64{100, 200, 300, 400, 500}
	p50 := percentileInt64(sorted, 50)
	if p50 != 300 {
		t.Errorf("p50 = %d, want 300", p50)
	}
	p99 := percentileInt64(sorted, 99)
	if p99 != 500 {
		t.Errorf("p99 = %d, want 500", p99)
	}
	empty := percentileInt64(nil, 50)
	if empty != 0 {
		t.Errorf("percentile of empty = %d, want 0", empty)
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{2*time.Minute + 30*time.Second, "2m 30s"},
		{3*time.Hour + 15*time.Minute, "3h 15m 0s"},
		{26*time.Hour + 30*time.Minute, "1d 2h 30m 0s"},
	}
	for _, tt := range tests {
		got := formatUptime(tt.d)
		if got != tt.want {
			t.Errorf("formatUptime(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestSeverityClass(t *testing.T) {
	tests := []struct {
		sev  analysis.Severity
		want string
	}{
		{analysis.CRITICAL, "critical"},
		{analysis.WARNING, "warning"},
		{analysis.INFO, "info"},
		{analysis.Severity(999), "info"},
	}
	for _, tt := range tests {
		got := severityClass(tt.sev)
		if got != tt.want {
			t.Errorf("severityClass(%v) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestTimeAgo(t *testing.T) {
	now := time.Now()
	tests := []struct {
		t    time.Time
		want string
	}{
		{now.Add(-30 * time.Second), "30s ago"},
		{now.Add(-45 * time.Minute), "45m ago"},
		{now.Add(-2 * time.Hour), "2h ago"},
		{now.Add(-48 * time.Hour), "2d ago"},
	}
	for _, tt := range tests {
		got := timeAgo(tt.t)
		if got != tt.want {
			t.Errorf("timeAgo(%v) = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestFormatTime(t *testing.T) {
	tm := time.Date(2023, 10, 27, 15, 30, 45, 0, time.UTC)
	want := "2023-10-27 15:30:45"
	got := formatTime(tm)
	if got != want {
		t.Errorf("formatTime() = %q, want %q", got, want)
	}
}

func TestSeq(t *testing.T) {
	tests := []struct {
		start, end int
		want       []int
	}{
		{1, 5, []int{1, 2, 3, 4, 5}},
		{3, 3, []int{3}},
	}
	for _, tt := range tests {
		got := seq(tt.start, tt.end)
		if len(got) != len(tt.want) {
			t.Errorf("seq(%d, %d) returned slice of length %d, want %d", tt.start, tt.end, len(got), len(tt.want))
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("seq(%d, %d)[%d] = %d, want %d", tt.start, tt.end, i, got[i], tt.want[i])
			}
		}
	}
}

func TestFormatAS(t *testing.T) {
	tests := []struct {
		asn  uint32
		want string
	}{
		{0, "Private/Unknown"},
		{15169, "AS15169 (Google)"},
		{13335, "AS13335 (Cloudflare)"},
		{999999, "AS999999 (AS999999)"},
	}
	for _, tt := range tests {
		got := formatAS(tt.asn)
		if got != tt.want {
			t.Errorf("formatAS(%d) = %q, want %q", tt.asn, got, tt.want)
		}
	}
}
