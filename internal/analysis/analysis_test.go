package analysis

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func makeFlow(src, dst string, srcPort, dstPort uint16, proto uint8, bytes, pkts uint64) model.Flow {
	return model.Flow{
		Timestamp:  time.Now(),
		SrcAddr:    net.ParseIP(src),
		DstAddr:    net.ParseIP(dst),
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Protocol:   proto,
		Bytes:      bytes,
		Packets:    pkts,
		Duration:   5 * time.Second,
		ExporterIP: net.ParseIP("10.0.0.1"),
	}
}

func defaultCfg() config.AnalysisConfig {
	return config.AnalysisConfig{
		Interval:              60 * time.Second,
		TopTalkersCount:       10,
		AnomalyBaselineWindow: 7 * 24 * time.Hour,
		ScanThreshold:         500,
	}
}

// --- Advisory tests ---

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{INFO, "INFO"},
		{WARNING, "WARNING"},
		{CRITICAL, "CRITICAL"},
	}
	for _, tt := range tests {
		got := tt.sev.String()
		if got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// --- Engine tests ---

func TestEngine_RunsAnalyzers(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Single host = 100% traffic → CRITICAL advisory (exceeds 25% threshold).
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 10000, 100),
	})

	cfg := defaultCfg()
	cfg.Interval = 50 * time.Millisecond

	engine := NewEngine(cfg, rb, TopTalkers{})
	go engine.Start()
	time.Sleep(100 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) == 0 {
		t.Error("engine should produce at least one advisory")
	}
}

func TestEngine_EmptyStore(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	cfg := defaultCfg()

	engine := NewEngine(cfg, rb, TopTalkers{}, ProtocolDistribution{}, ScanDetector{})
	go engine.Start()
	time.Sleep(50 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestEngine_SortsBySeverity(t *testing.T) {
	rb := storage.NewRingBuffer(10000)

	// One dominant source (>50% = CRITICAL) and one at ~30% (WARNING).
	flows := []model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 70000, 700),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 80, 6, 30000, 300),
	}
	rb.Insert(flows)

	cfg := defaultCfg()
	cfg.TopTalkersCount = 2

	engine := NewEngine(cfg, rb, TopTalkers{})
	go engine.Start()
	time.Sleep(50 * time.Millisecond)
	engine.Stop()

	advisories := engine.Advisories()
	if len(advisories) < 2 {
		t.Fatalf("expected at least 2 advisories, got %d", len(advisories))
	}
	// First should be highest severity.
	if advisories[0].Severity < advisories[len(advisories)-1].Severity {
		t.Error("advisories should be sorted with highest severity first")
	}
}

// --- Top Talkers tests ---

func TestTopTalkers_SingleHost(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 10000, 100),
	})

	advisories := TopTalkers{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("single host = 100%% traffic should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestTopTalkers_MultipleHosts(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 80, 6, 3000, 30),
		makeFlow("10.0.1.3", "192.168.1.1", 1236, 80, 6, 2000, 20),
	})

	cfg := defaultCfg()
	cfg.TopTalkersCount = 3
	advisories := TopTalkers{}.Analyze(rb, cfg)

	// 10.0.1.1 = 50% (CRITICAL), 10.0.1.2 = 30% (WARNING), 10.0.1.3 = 20% (<25%, filtered)
	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories (hosts above 25%%), got %d", len(advisories))
	}

	// First should be 10.0.1.1 (highest bytes).
	if advisories[0].Title != "Top Talker: 10.0.1.1" {
		t.Errorf("first talker should be 10.0.1.1, got %q", advisories[0].Title)
	}
}

func TestTopTalkers_Limit(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	for i := 0; i < 20; i++ {
		f := makeFlow("10.0.1."+fmt.Sprintf("%d", i), "192.168.1.1", uint16(1000+i), 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	cfg := defaultCfg()
	cfg.TopTalkersCount = 5
	advisories := TopTalkers{}.Analyze(rb, cfg)

	// 20 hosts each at 5% — none exceed 25% threshold, so no advisories.
	if len(advisories) != 0 {
		t.Errorf("no host above 25%% should produce 0 advisories, got %d", len(advisories))
	}
}

func TestTopTalkers_DominantHost(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// One host at ~67%, another at ~33% — both above 25%.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 20000, 200),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 80, 6, 10000, 100),
	})

	cfg := defaultCfg()
	cfg.TopTalkersCount = 5
	advisories := TopTalkers{}.Analyze(rb, cfg)

	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories (both above 25%%), got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("67%% host should be CRITICAL, got %s", advisories[0].Severity)
	}
	if advisories[1].Severity != WARNING {
		t.Errorf("33%% host should be WARNING, got %s", advisories[1].Severity)
	}
}

func TestTopTalkers_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := TopTalkers{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

// --- Protocol Distribution tests ---

func TestProtocolDistribution_Normal(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 7000, 70),   // TCP
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 53, 17, 2000, 20),  // UDP
		makeFlow("10.0.1.3", "192.168.1.1", 0, 0, 1, 1000, 10),       // ICMP
	})

	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	// Normal distribution should produce NO advisories — silence is a feature.
	if len(advisories) != 0 {
		t.Errorf("normal protocol distribution should produce 0 advisories, got %d", len(advisories))
	}
}

func TestProtocolDistribution_ICMPFlood(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 0, 0, 1, 8000, 80),    // ICMP dominant
		makeFlow("10.0.1.2", "192.168.1.1", 1234, 80, 6, 2000, 20), // TCP minor
	})

	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	hasWarning := false
	for _, a := range advisories {
		if a.Severity == WARNING {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Error("ICMP >10% should generate WARNING")
	}
}

func TestProtocolDistribution_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := ProtocolDistribution{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

// --- Port Scan Detector tests ---

func TestScanDetector_NoScan(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50),
		makeFlow("10.0.1.1", "192.168.1.1", 1235, 443, 6, 3000, 30),
	})

	advisories := ScanDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("2 ports should not trigger scan, got %d advisories", len(advisories))
	}
}

func TestScanDetector_ScanDetected(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Simulate a port scan: one source hits 600 unique ports.
	var flows []model.Flow
	for i := 0; i < 600; i++ {
		flows = append(flows, makeFlow("10.0.1.100", "192.168.1.1", 50000, uint16(i+1), 6, 100, 1))
	}
	rb.Insert(flows)

	cfg := defaultCfg()
	cfg.ScanThreshold = 500

	advisories := ScanDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 scan advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("600 ports (threshold 500) should be WARNING, got %s", advisories[0].Severity)
	}
}

func TestScanDetector_CriticalScan(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Simulate a massive scan: 1500+ unique ports (>= 3x threshold of 500).
	var flows []model.Flow
	for i := 0; i < 1600; i++ {
		flows = append(flows, makeFlow("10.0.1.200", "192.168.1.1", 50000, uint16(i+1), 6, 100, 1))
	}
	rb.Insert(flows)

	cfg := defaultCfg()
	cfg.ScanThreshold = 500

	advisories := ScanDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 scan advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("1600 ports (>= 3x 500) should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestScanDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := ScanDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestScanDetector_IgnoresNonTCPUDP(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// ICMP flows to many destinations shouldn't trigger scan detection.
	var flows []model.Flow
	for i := 0; i < 600; i++ {
		flows = append(flows, makeFlow("10.0.1.100", "192.168.1.1", 0, 0, 1, 100, 1))
	}
	rb.Insert(flows)

	advisories := ScanDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("ICMP flows should not trigger scan detection, got %d advisories", len(advisories))
	}
}

// --- Formatting helpers tests ---

func TestFormatBytesShort(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
	}
	for _, tt := range tests {
		got := formatBytesShort(tt.input)
		if got != tt.want {
			t.Errorf("formatBytesShort(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatCountShort(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{42, "42"},
		{1500, "1.5K"},
		{1500000, "1.5M"},
	}
	for _, tt := range tests {
		got := formatCountShort(tt.input)
		if got != tt.want {
			t.Errorf("formatCountShort(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- Anomaly Detection tests ---

func TestAnomalyDetector_NoData(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := AnomalyDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestAnomalyDetector_Spike(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Create baseline buckets with consistent ~1000 bytes each.
	for i := 2; i <= 9; i++ {
		for j := 0; j < 10; j++ {
			f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 100, 1)
			f.Timestamp = now.Add(-time.Duration(i) * time.Minute).Add(time.Duration(j) * time.Second)
			rb.Insert([]model.Flow{f})
		}
	}

	// Current window: massive spike (100x baseline).
	for j := 0; j < 100; j++ {
		f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 10000, 100)
		f.Timestamp = now.Add(-time.Duration(j) * time.Second)
		rb.Insert([]model.Flow{f})
	}

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	hasSpike := false
	for _, a := range advisories {
		if a.Title == "Traffic Spike Detected" {
			hasSpike = true
		}
	}
	if !hasSpike {
		t.Error("should detect traffic spike when current >> baseline")
	}
}

func TestAnomalyDetector_Drop(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Create baseline with substantial traffic.
	for i := 2; i <= 9; i++ {
		for j := 0; j < 20; j++ {
			f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
			f.Timestamp = now.Add(-time.Duration(i) * time.Minute).Add(time.Duration(j) * time.Second)
			rb.Insert([]model.Flow{f})
		}
	}

	// Current window: almost no traffic (< 25% of baseline).
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 10, 1)
	f.Timestamp = now.Add(-5 * time.Second)
	rb.Insert([]model.Flow{f})

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	hasDrop := false
	for _, a := range advisories {
		if a.Title == "Traffic Drop Detected" {
			hasDrop = true
		}
	}
	if !hasDrop {
		t.Error("should detect traffic drop when current << baseline")
	}
}

func TestAnomalyDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// All buckets have similar traffic — current and baseline all ~10K bytes.
	for i := 0; i < 9; i++ {
		for j := 0; j < 10; j++ {
			f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000, 10)
			// Place flows at distinct past times: 10s, 20s, ... into each minute.
			f.Timestamp = now.Add(-time.Duration(i)*time.Minute - time.Duration(j+1)*5*time.Second)
			rb.Insert([]model.Flow{f})
		}
	}

	advisories := AnomalyDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		for _, a := range advisories {
			t.Logf("  advisory: %s — %s", a.Title, a.Description)
		}
		t.Errorf("normal traffic should produce 0 advisories, got %d", len(advisories))
	}
}

// --- DNS Volume tests ---

func TestDNSVolume_NoData(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestDNSVolume_NoDNS(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 443, 6, 3000, 30),
	})

	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("no DNS flows should produce 0 advisories, got %d", len(advisories))
	}
}

func TestDNSVolume_HighRate(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Insert 2000 DNS flows over 10 minutes = 200/min (above 100/min threshold).
	for i := 0; i < 2000; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i%10000), 53, 17, 100, 1)
		rb.Insert([]model.Flow{f})
	}
	// Some non-DNS traffic.
	for i := 0; i < 100; i++ {
		f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	hasRateAdvisory := false
	for _, a := range advisories {
		if a.Title == "High DNS Query Rate" {
			hasRateAdvisory = true
		}
	}
	if !hasRateAdvisory {
		t.Error("2000 DNS flows in 10min should trigger High DNS Query Rate")
	}
}

func TestDNSVolume_HighRatio(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// 80% DNS flows.
	for i := 0; i < 800; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i%10000), 53, 17, 100, 1)
		rb.Insert([]model.Flow{f})
	}
	for i := 0; i < 200; i++ {
		f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	hasRatioAdvisory := false
	for _, a := range advisories {
		if a.Title == "High DNS Traffic Ratio" {
			hasRatioAdvisory = true
		}
	}
	if !hasRatioAdvisory {
		t.Error("80% DNS ratio should trigger High DNS Traffic Ratio")
	}
}

func TestDNSVolume_NormalDNS(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// 50 DNS flows in 10 min = 5/min (well under threshold).
	for i := 0; i < 50; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i), 53, 17, 100, 1)
		rb.Insert([]model.Flow{f})
	}
	// 1000 non-DNS flows (DNS is ~5% of total).
	for i := 0; i < 1000; i++ {
		f := makeFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal DNS volume should produce 0 advisories, got %d", len(advisories))
	}
}

func TestDNSVolume_TCPPort53(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// TCP DNS flows should also be counted.
	for i := 0; i < 2000; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i%10000), 53, 6, 100, 1)
		rb.Insert([]model.Flow{f})
	}

	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	hasAdvisory := false
	for _, a := range advisories {
		if a.Title == "High DNS Query Rate" || a.Title == "High DNS Traffic Ratio" {
			hasAdvisory = true
		}
	}
	if !hasAdvisory {
		t.Error("TCP DNS flows should also be detected")
	}
}

// --- Flow Asymmetry tests ---

func TestFlowAsymmetry_NoData(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestFlowAsymmetry_Symmetric(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Symmetric traffic: A→B and B→A with similar bytes.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 5000, 50),
		makeFlow("192.168.1.1", "10.0.1.1", 80, 1234, 6, 4500, 45),
	})

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("symmetric traffic should produce 0 advisories, got %d", len(advisories))
	}
}

func TestFlowAsymmetry_Asymmetric(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Highly asymmetric: A sends 1MB, B sends almost nothing back.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 1000000, 1000),
		makeFlow("192.168.1.1", "10.0.1.1", 80, 1234, 6, 500, 5),
	})

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 asymmetry advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("2000:1 ratio should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestFlowAsymmetry_Unidirectional(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Only A→B, no return traffic.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 500000, 500),
	})

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 asymmetry advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("unidirectional traffic should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestFlowAsymmetry_BelowMinBytes(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Asymmetric but small flows (under 100KB threshold).
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 500, 5),
	})

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("small flows should not trigger asymmetry, got %d advisories", len(advisories))
	}
}

func TestFlowAsymmetry_ModerateAsymmetry(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// 15:1 ratio with enough volume to trigger — WARNING level.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 150000, 150),
		makeFlow("192.168.1.1", "10.0.1.1", 80, 1234, 6, 10000, 10),
	})

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("15:1 ratio should be WARNING, got %s", advisories[0].Severity)
	}
}

func TestFlowAsymmetry_Limit(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	// Create 20 asymmetric pairs — should be limited to top 10.
	for i := 0; i < 20; i++ {
		src := fmt.Sprintf("10.0.1.%d", i+1)
		f := makeFlow(src, "192.168.1.1", uint16(1234+i), 80, 6, uint64(500000+i*10000), 500)
		rb.Insert([]model.Flow{f})
	}

	advisories := FlowAsymmetry{}.Analyze(rb, defaultCfg())
	if len(advisories) > 10 {
		t.Errorf("expected at most 10 advisories, got %d", len(advisories))
	}
}

// --- Engine Advisory History tests ---

func TestEngine_AdvisoryHistory(t *testing.T) {
	rb := storage.NewRingBuffer(10000)

	// First cycle: insert a dominant host to trigger CRITICAL.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 100000, 1000),
	})

	cfg := defaultCfg()
	cfg.Interval = 50 * time.Millisecond
	cfg.TopTalkersCount = 1

	engine := NewEngine(cfg, rb, TopTalkers{})
	go engine.Start()
	time.Sleep(80 * time.Millisecond)

	// Should have the advisory.
	advisories := engine.Advisories()
	if len(advisories) == 0 {
		t.Fatal("expected at least 1 advisory after first cycle")
	}
	if advisories[0].Resolved {
		t.Error("active advisory should not be resolved")
	}

	// Dilute the ring buffer: add enough traffic from many hosts to push
	// 10.0.1.1 well below the 25% threshold.
	for i := 0; i < 200; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.2.%d", i), "192.168.1.1", uint16(2000+i), 80, 6, 5000, 50),
		})
	}

	time.Sleep(80 * time.Millisecond)
	engine.Stop()

	advisories = engine.Advisories()
	// The old advisory should still be present but marked resolved.
	foundResolved := false
	for _, a := range advisories {
		if a.Title == "Top Talker: 10.0.1.1" && a.Resolved {
			foundResolved = true
		}
	}
	if !foundResolved {
		t.Error("old advisory should be present and marked as resolved")
	}
}

// --- Retransmission Detector tests ---

func TestRetransmissionDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestRetransmissionDetector_NormalTCP(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Normal TCP: 1000 bytes/pkt average — well above smallPacketThreshold.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 50),
	})

	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal TCP should produce 0 advisories, got %d", len(advisories))
	}
}

func TestRetransmissionDetector_SmallPackets(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Small packets: 40 bytes/pkt (likely retransmissions) with enough packets.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 2400, 60),
	})

	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for small packets, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("40 bytes/pkt should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestRetransmissionDetector_IgnoresUDP(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// UDP with small packets — should not trigger.
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 53, 17, 2400, 60),
	})

	advisories := RetransmissionDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("UDP flows should not trigger retransmission detection, got %d", len(advisories))
	}
}

// --- Unreachable Host Detector tests ---

func TestUnreachableDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestUnreachableDetector_HealthyService(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Normal flows — large bytes, not tiny.
	for i := 0; i < 50; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", uint16(1000+i), 80, 6, 5000, 50),
		})
	}

	advisories := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("healthy service should produce 0 advisories, got %d", len(advisories))
	}
}

func TestUnreachableDetector_DownService(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	// Many tiny flows from multiple sources → service appears down.
	for i := 0; i < 30; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.100", uint16(1000+i), 443, 6, 60, 1),
		})
	}

	advisories := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for unreachable service, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("30 tiny flows from 30 sources should be CRITICAL, got %s", advisories[0].Severity)
	}
}

// --- New Talker Detector tests ---

func TestNewTalkerDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := NewTalkerDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestNewTalkerDetector_AllKnownHosts(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: host was active 5 minutes ago.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: same host is still active.
	f2 := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("known host should produce 0 advisories, got %d", len(advisories))
	}
}

func TestNewTalkerDetector_NewHost(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: only 10.0.1.1 was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: new host 10.0.1.99 appears with significant traffic.
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for new host, got %d", len(advisories))
	}
	if advisories[0].Title != "New Talker: 10.0.1.99" {
		t.Errorf("expected advisory for 10.0.1.99, got %q", advisories[0].Title)
	}
}

func TestNewTalkerDetector_SmallTrafficIgnored(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	cfg := defaultCfg()
	cfg.Interval = 1 * time.Minute

	now := time.Now()
	// Baseline: host was active.
	f := makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 50000, 500)
	f.Timestamp = now.Add(-5 * time.Minute)
	rb.Insert([]model.Flow{f})

	// Recent: new host with tiny traffic (below threshold).
	f2 := makeFlow("10.0.1.99", "192.168.1.1", 1234, 80, 6, 100, 1)
	f2.Timestamp = now.Add(-10 * time.Second)
	rb.Insert([]model.Flow{f2})

	advisories := NewTalkerDetector{}.Analyze(rb, cfg)
	if len(advisories) != 0 {
		t.Errorf("small traffic new host should be ignored, got %d advisories", len(advisories))
	}
}

// --- Port Concentration Detector tests ---

func TestPortConcentrationDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationDetector_Normal(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Few sources to one port — normal.
	for i := 0; i < 5; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", uint16(1000+i), 80, 6, 5000, 50),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("5 sources to one port should produce 0 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationDetector_HighConcentration(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	// 25 unique sources all hitting the same port.
	for i := 0; i < 25; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", uint16(50000+i), 443, 6, 5000, 50),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for high port concentration, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("25 sources should be WARNING, got %s", advisories[0].Severity)
	}
}

func TestPortConcentrationDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	// 60+ unique sources (>= 3x threshold of 20) → CRITICAL.
	for i := 0; i < 65; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.%d.%d", i/256, i%256), "192.168.1.1", uint16(50000+i), 22, 6, 100, 1),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("65 sources (>= 3x20) should be CRITICAL, got %s", advisories[0].Severity)
	}
}
