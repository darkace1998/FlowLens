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

	// Insert flows that will generate different severity levels.
	// One dominant source (>50% = CRITICAL) and one minor source.
	flows := []model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1234, 80, 6, 90000, 900),
		makeFlow("10.0.1.2", "192.168.1.1", 1235, 80, 6, 1000, 10),
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

	if len(advisories) != 3 {
		t.Fatalf("expected 3 advisories, got %d", len(advisories))
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

	if len(advisories) != 5 {
		t.Errorf("expected 5 advisories (limited), got %d", len(advisories))
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
	if len(advisories) == 0 {
		t.Fatal("should produce at least one advisory")
	}

	// Normal distribution should produce INFO summary.
	hasInfo := false
	for _, a := range advisories {
		if a.Severity == INFO {
			hasInfo = true
		}
	}
	if !hasInfo {
		t.Error("normal distribution should include an INFO advisory")
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
