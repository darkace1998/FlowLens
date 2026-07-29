package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestExposedServiceDetector(t *testing.T) {
	detector := ExposedServiceDetector{}
	store := storage.NewRingBuffer(100)
	cfg := defaultCfg()
	now := time.Now()

	// Helper to parse IP
	ip := func(s string) net.IP {
		return net.ParseIP(s)
	}

	flows := []model.Flow{
		// 1. Private IP to SMB (445) - should not trigger
		{
			Timestamp: now,
			SrcAddr:   ip("192.168.1.10"),
			DstAddr:   ip("10.0.0.5"),
			SrcPort:   12345,
			DstPort:   445,
			Protocol:  6,
		},
		// 2. Public IP to HTTP (80) - not a sensitive port, should not trigger
		{
			Timestamp: now,
			SrcAddr:   ip("8.8.8.8"),
			DstAddr:   ip("10.0.0.5"),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  6,
		},
		// 3. Public IP to RDP (3389) - sensitive port, should trigger CRITICAL
		{
			Timestamp: now,
			SrcAddr:   ip("8.8.8.8"),
			DstAddr:   ip("10.0.0.5"),
			SrcPort:   12345,
			DstPort:   3389,
			Protocol:  6,
		},
		// 4. Empty IPs - should not panic and should not trigger
		{
			Timestamp: now,
			SrcAddr:   nil,
			DstAddr:   nil,
			SrcPort:   12345,
			DstPort:   3306,
			Protocol:  6,
		},
		// 5. Loopback IP to PostgreSQL (5432) - should not trigger
		{
			Timestamp: now,
			SrcAddr:   ip("127.0.0.1"),
			DstAddr:   ip("127.0.0.1"),
			SrcPort:   12345,
			DstPort:   5432,
			Protocol:  6,
		},
		// 6. Public IP to SMB (445) via UDP (17) - sensitive port, should trigger
		{
			Timestamp: now,
			SrcAddr:   ip("1.1.1.1"),
			DstAddr:   ip("10.0.0.5"),
			SrcPort:   12345,
			DstPort:   445,
			Protocol:  17,
		},
		// 7. Non-unicast (multicast) to MongoDB (27017) - should not trigger
		{
			Timestamp: now,
			SrcAddr:   ip("224.0.0.1"),
			DstAddr:   ip("10.0.0.5"),
			SrcPort:   12345,
			DstPort:   27017,
			Protocol:  6,
		},
	}

	_ = store.Insert(flows)

	advisories := detector.Analyze(store, cfg)

	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advisories))
	}

	// Verify the advisories
	foundRDP := false
	foundSMB := false
	for _, adv := range advisories {
		if adv.Severity != CRITICAL {
			t.Errorf("expected CRITICAL severity, got %v", adv.Severity)
		}
		if adv.Title == "Exposed Service: RDP on 10.0.0.5" {
			foundRDP = true
		}
		if adv.Title == "Exposed Service: SMB on 10.0.0.5" {
			foundSMB = true
		}
	}

	if !foundRDP {
		t.Errorf("missing advisory for RDP")
	}
	if !foundSMB {
		t.Errorf("missing advisory for SMB")
	}
}

func TestExposedServiceDetector_Empty(t *testing.T) {
	detector := ExposedServiceDetector{}
	store := storage.NewRingBuffer(10)
	cfg := defaultCfg()

	advisories := detector.Analyze(store, cfg)
	if advisories != nil {
		t.Errorf("expected nil advisories for empty store, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_Error(t *testing.T) {
	detector := ExposedServiceDetector{}
	store := mockErrorStorage{}
	cfg := defaultCfg()

	advisories := detector.Analyze(store, cfg)
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %d", len(advisories))
	}
}
