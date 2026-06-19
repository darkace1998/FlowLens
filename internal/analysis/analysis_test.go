package analysis

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"

	"github.com/darkace1998/FlowLens/internal/util"
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
	engine.Start()
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
	engine.Start()
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
	engine.Start()
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
		got := util.FormatBytes(tt.input)
		if got != tt.want {
			t.Errorf("util.FormatBytes(%d) = %q, want %q", tt.input, got, tt.want)
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
		got := util.FormatCount(tt.input)
		if got != tt.want {
			t.Errorf("util.FormatCount(%d) = %q, want %q", tt.input, got, tt.want)
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
	engine.Start()
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
