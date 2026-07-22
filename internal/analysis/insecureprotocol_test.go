package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestInsecureProtocolDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	advisories := InsecureProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestInsecureProtocolDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	flows := []model.Flow{
		makeTestFlow("10.0.0.1", "10.0.0.2", 12345, 80, 6, 100, 1),
		makeTestFlow("10.0.0.2", "10.0.0.1", 80, 12345, 6, 1000, 10),
		makeTestFlow("10.0.0.1", "10.0.0.2", 12345, 443, 6, 100, 1),
	}
	rb.Insert(flows)

	advisories := InsecureProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("normal traffic should produce 0 advisories, got %d", len(advisories))
	}
}

func TestInsecureProtocolDetector_FTPTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	flows := []model.Flow{
		// Client to Server
		makeTestFlow("10.0.0.1", "10.0.0.50", 12345, 21, 6, 500, 5),
		// Server to Client
		makeTestFlow("10.0.0.50", "10.0.0.1", 21, 12345, 6, 1000, 10),
	}
	rb.Insert(flows)

	advisories := InsecureProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	if adv.Severity != WARNING {
		t.Errorf("expected WARNING severity, got %s", adv.Severity)
	}

	expectedTitle := "Insecure Protocol Used: FTP (10.0.0.50)"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}

func TestInsecureProtocolDetector_SyslogIgnored(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	flows := []model.Flow{
		// Syslog (UDP 514)
		makeTestFlow("10.0.0.1", "10.0.0.50", 12345, 514, 17, 500, 5),
	}
	rb.Insert(flows)

	advisories := InsecureProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for syslog UDP, got %d", len(advisories))
	}

	flows2 := []model.Flow{
		// rsh (TCP 514)
		makeTestFlow("10.0.0.1", "10.0.0.51", 12345, 514, 6, 500, 5),
	}
	rb.Insert(flows2)
	advisories2 := InsecureProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories2) != 1 {
		t.Errorf("expected 1 advisory for rsh TCP, got %d", len(advisories2))
	}
	expectedTitle := "Insecure Protocol Used: rsh (10.0.0.51)"
	if advisories2[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories2[0].Title)
	}
}

func TestInsecureProtocolDetector_MultipleClients(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	flows := make([]model.Flow, 0, 5)
	for i := 0; i < 5; i++ {
		clientIP := fmt.Sprintf("10.0.0.%d", 100+i)
		flows = append(flows, makeTestFlow(clientIP, "10.0.0.50", 12345, 23, 6, 100, 1)) // Telnet
	}
	rb.Insert(flows)

	advisories := InsecureProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	adv := advisories[0]
	expectedTitle := "Insecure Protocol Used: Telnet (10.0.0.50)"
	if adv.Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, adv.Title)
	}
}

func TestInsecureProtocolDetector_StorageError(t *testing.T) {
	advisories := InsecureProtocolDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil on error, got %v", advisories)
	}
}
