package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"time"
)

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

// TestDNSVolume_TinyWindow tests the path where the query window might be missing
// or empty. Since the default queryWindow() fallback in engine.go ensures the duration is positive,
// we just need to ensure the analyzer handles it cleanly, or provide a custom small window
// to simulate the logic if possible. However, the condition windowMins <= 0 acts as a safety
// guard. We can verify it works by invoking it directly.
func TestDNSVolume_TinyWindow(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	f := makeFlow("10.0.1.1", "8.8.8.8", 30000, 53, 17, 100, 1)
	rb.Insert([]model.Flow{f})

	// Create an AnalysisConfig where we try to trick the query window or
	// ensure coverage of the guard using an indirect way.
	cfg := defaultCfg()
	cfg.QueryWindow = 1 * time.Nanosecond // Less than a minute, so Minutes() is ~0

	advisories := DNSVolume{}.Analyze(rb, cfg)

	// Because 1 flow / 1 min (fallback) = 1/min (below threshold of 100).
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for tiny window test, got %d", len(advisories))
	}
}

// We must test all conditions.
// The dnsRateAction for INFO/WARNING and CRITICAL
// The dnsRatioAction for INFO/WARNING and CRITICAL
func TestDNSRateAction(t *testing.T) {
	if a := dnsRateAction(CRITICAL); a != "Investigate DNS traffic immediately — extremely high query rate may indicate tunneling or amplification attack." {
		t.Errorf("unexpected CRITICAL action: %s", a)
	}
	if a := dnsRateAction(WARNING); a != "Review DNS query sources — elevated rate may indicate misconfigured resolver or data exfiltration." {
		t.Errorf("unexpected WARNING action: %s", a)
	}
}

func TestDNSRatioAction(t *testing.T) {
	if a := dnsRatioAction(CRITICAL); a != "Investigate immediately — DNS is dominating traffic, likely tunneling or amplification." {
		t.Errorf("unexpected CRITICAL action: %s", a)
	}
	if a := dnsRatioAction(WARNING); a != "Review DNS sources and destinations — disproportionate DNS volume detected." {
		t.Errorf("unexpected WARNING action: %s", a)
	}
}

func TestDNSVolume_StorageError(t *testing.T) {
	advisories := DNSVolume{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestDNSVolume_ConfigThresholds(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Threshold is normally 100/min. We set it to 10/min.
	cfg := defaultCfg()
	cfg.DNSRateThreshold = 10
	cfg.DNSRatioThreshold = 50.0
	cfg.QueryWindow = 1 * time.Minute

	// 20 DNS flows in 1 min = 20/min (above 10/min threshold).
	for i := 0; i < 20; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i), 53, 17, 100, 1)
		rb.Insert([]model.Flow{f})
	}

	// 80 non-DNS flows -> 20% DNS ratio (below 50% threshold).
	for i := 0; i < 80; i++ {
		f := makeFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	advisories := DNSVolume{}.Analyze(rb, cfg)

	hasRate := false
	hasRatio := false
	for _, a := range advisories {
		if a.Title == "High DNS Query Rate" {
			hasRate = true
		}
		if a.Title == "High DNS Traffic Ratio" {
			hasRatio = true
		}
	}

	if !hasRate {
		t.Error("expected rate advisory due to custom threshold")
	}
	if hasRatio {
		t.Error("did not expect ratio advisory due to custom threshold")
	}
}

func TestDNSVolume_Name(t *testing.T) {
	if name := (DNSVolume{}).Name(); name != "DNS Volume" {
		t.Errorf("expected 'DNS Volume', got %q", name)
	}
}

func TestDNSVolume_CriticalActions(t *testing.T) {
	rb := storage.NewRingBuffer(10000)

	// 500 DNS flows in 1 min = 500/min (above 100*5 threshold for CRITICAL)
	// and 500/500 = 100% ratio (above 60% threshold for CRITICAL)
	for i := 0; i < 500; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i), 53, 17, 100, 1)
		rb.Insert([]model.Flow{f})
	}

	cfg := defaultCfg()
	cfg.QueryWindow = 1 * time.Minute

	advisories := DNSVolume{}.Analyze(rb, cfg)

	for _, a := range advisories {
		if a.Severity != CRITICAL {
			t.Errorf("expected CRITICAL severity, got %s", a.Severity)
		}
		if a.Title == "High DNS Query Rate" && a.Action != "Investigate DNS traffic immediately — extremely high query rate may indicate tunneling or amplification attack." {
			t.Errorf("unexpected action for critical rate: %s", a.Action)
		}
		if a.Title == "High DNS Traffic Ratio" && a.Action != "Investigate immediately — DNS is dominating traffic, likely tunneling or amplification." {
			t.Errorf("unexpected action for critical ratio: %s", a.Action)
		}
	}
}

func TestDNSVolume_WarningRatioAction(t *testing.T) {
	rb := storage.NewRingBuffer(10000)

	// DNS ratio of 40% -> WARNING level (between 30% and 60%)
	for i := 0; i < 40; i++ {
		f := makeFlow("10.0.1.1", "8.8.8.8", uint16(30000+i), 53, 17, 100, 1)
		rb.Insert([]model.Flow{f})
	}
	for i := 0; i < 60; i++ {
		f := makeFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, 6, 1000, 10)
		rb.Insert([]model.Flow{f})
	}

	advisories := DNSVolume{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %s", advisories[0].Severity)
	}
	if advisories[0].Action != "Review DNS sources and destinations — disproportionate DNS volume detected." {
		t.Errorf("unexpected action for warning ratio: %s", advisories[0].Action)
	}
}
