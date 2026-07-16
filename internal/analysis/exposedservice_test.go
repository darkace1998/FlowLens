package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestExposedServiceDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_Error(t *testing.T) {
	advisories := ExposedServiceDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on error, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_InternalToInternal(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	rb.Insert([]model.Flow{
		makeFlow("10.0.0.1", "10.0.0.2", 50000, 22, 6, 1000, 10),
		makeFlow("192.168.1.100", "192.168.1.200", 50001, 3389, 6, 1000, 10),
		makeFlow("172.16.0.10", "172.16.0.20", 50002, 3306, 6, 1000, 10),
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for internal traffic, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_PublicToPublic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	rb.Insert([]model.Flow{
		makeFlow("8.8.8.8", "1.1.1.1", 50000, 22, 6, 1000, 10),
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for public-to-public traffic, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_ExposedSSH(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	rb.Insert([]model.Flow{
		// Public to internal on port 22
		makeFlow("203.0.113.5", "10.0.0.50", 50000, 22, 6, 1500, 15),
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != WARNING {
		t.Errorf("expected severity WARNING, got %s", adv.Severity)
	}
	expectedTitle := "Exposed Service: 10.0.0.50 (SSH)"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}

func TestExposedServiceDetector_ExposedRDP_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	rb.Insert([]model.Flow{
		// 6 different public IPs targeting internal RDP
		makeFlow("203.0.113.1", "192.168.1.100", 50001, 3389, 6, 1000, 10),
		makeFlow("203.0.113.2", "192.168.1.100", 50002, 3389, 6, 1000, 10),
		makeFlow("203.0.113.3", "192.168.1.100", 50003, 3389, 6, 1000, 10),
		makeFlow("203.0.113.4", "192.168.1.100", 50004, 3389, 6, 1000, 10),
		makeFlow("203.0.113.5", "192.168.1.100", 50005, 3389, 6, 1000, 10),
		makeFlow("203.0.113.6", "192.168.1.100", 50006, 3389, 6, 1000, 10),
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != CRITICAL {
		t.Errorf("expected severity CRITICAL, got %s", adv.Severity)
	}
	expectedTitle := "Exposed Service: 192.168.1.100 (RDP)"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}

func TestExposedServiceDetector_NonSensitivePort(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	rb.Insert([]model.Flow{
		// Public to internal on port 80 (HTTP) - not in sensitive ports list
		makeFlow("203.0.113.5", "10.0.0.50", 50000, 80, 6, 1500, 15),
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for non-sensitive port, got %d", len(advisories))
	}
}

func TestExposedServiceDetector_NonTCPUDP(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	rb.Insert([]model.Flow{
		// Public to internal on port 22, but protocol is ICMP (1)
		makeFlow("203.0.113.5", "10.0.0.50", 50000, 22, 1, 1500, 15),
	})

	advisories := ExposedServiceDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for non-TCP/UDP traffic, got %d", len(advisories))
	}
}
