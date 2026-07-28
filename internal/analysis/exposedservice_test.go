package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestExposedServiceDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on empty store, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_StorageError(t *testing.T) {
	advisories := ExposedServiceDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestExposedServiceDetector_PrivateToPrivate(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	rb.Insert([]model.Flow{
		{
			Timestamp: time.Now(),
			SrcAddr:   net.ParseIP("192.168.1.100"), // Private
			DstAddr:   net.ParseIP("10.0.0.5"),      // Private
			DstPort:   22,                           // SSH (sensitive)
			Protocol:  6,                            // TCP
		},
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for private-to-private traffic, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_PublicToPublic(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	rb.Insert([]model.Flow{
		{
			Timestamp: time.Now(),
			SrcAddr:   net.ParseIP("8.8.8.8"), // Public
			DstAddr:   net.ParseIP("1.1.1.1"), // Public
			DstPort:   22,                     // SSH (sensitive)
			Protocol:  6,                      // TCP
		},
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for public-to-public traffic, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_PublicToPrivate_NonSensitivePort(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	rb.Insert([]model.Flow{
		{
			Timestamp: time.Now(),
			SrcAddr:   net.ParseIP("8.8.8.8"),  // Public
			DstAddr:   net.ParseIP("10.0.0.5"), // Private
			DstPort:   443,                     // HTTPS (not in sensitive ports)
			Protocol:  6,                       // TCP
		},
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for non-sensitive port, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_PublicToPrivate_SensitivePort_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(10)
	rb.Insert([]model.Flow{
		{
			Timestamp: time.Now(),
			SrcAddr:   net.ParseIP("8.8.8.8"),  // Public
			DstAddr:   net.ParseIP("10.0.0.5"), // Private
			DstPort:   3389,                    // RDP (sensitive)
			Protocol:  6,                       // TCP
		},
		{
			Timestamp: time.Now(),
			SrcAddr:   net.ParseIP("8.8.4.4"),  // Public
			DstAddr:   net.ParseIP("10.0.0.5"), // Private
			DstPort:   3389,                    // RDP (sensitive)
			Protocol:  6,                       // TCP
		},
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != WARNING {
		t.Errorf("expected severity WARNING, got %s", adv.Severity)
	}

	expectedTitle := "Exposed Service: 10.0.0.5 (RDP)"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}

func TestExposedServiceDetector_PublicToPrivate_SensitivePort_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Create 6 flows from distinct public IPs to trigger CRITICAL threshold (> 5)
	flows := []model.Flow{
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("8.8.8.1"), DstAddr: net.ParseIP("192.168.1.10"), DstPort: 22, Protocol: 6},
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("8.8.8.2"), DstAddr: net.ParseIP("192.168.1.10"), DstPort: 22, Protocol: 6},
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("8.8.8.3"), DstAddr: net.ParseIP("192.168.1.10"), DstPort: 22, Protocol: 6},
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("8.8.8.4"), DstAddr: net.ParseIP("192.168.1.10"), DstPort: 22, Protocol: 6},
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("8.8.8.5"), DstAddr: net.ParseIP("192.168.1.10"), DstPort: 22, Protocol: 6},
		{Timestamp: time.Now(), SrcAddr: net.ParseIP("8.8.8.6"), DstAddr: net.ParseIP("192.168.1.10"), DstPort: 22, Protocol: 6},
	}
	rb.Insert(flows)

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != CRITICAL {
		t.Errorf("expected severity CRITICAL for > 5 sources, got %s", adv.Severity)
	}

	expectedTitle := "Exposed Service: 192.168.1.10 (SSH)"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}
