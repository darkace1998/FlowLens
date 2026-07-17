package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestInsecureProtocolDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := InsecureProtocolDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestInsecureProtocolDetector_StorageError(t *testing.T) {
	detector := InsecureProtocolDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestInsecureProtocolDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// SSH (22)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 22, 6, 1000, 20)
	rb.Insert([]model.Flow{f1})

	// HTTPS (443)
	f2 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 443, 6, 5000, 50)
	rb.Insert([]model.Flow{f2})

	// Secure IMAP (993)
	f3 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 993, 6, 2000, 30)
	rb.Insert([]model.Flow{f3})

	// UDP traffic on port 80 (should be ignored, detector focuses on TCP)
	f4 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 17, 1000, 20)
	rb.Insert([]model.Flow{f4})

	detector := InsecureProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestInsecureProtocolDetector_BelowPacketThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// FTP (21) but only 5 packets (below threshold of 10)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 21, 6, 200, 5)
	rb.Insert([]model.Flow{f1})

	detector := InsecureProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories when below packet threshold, got %d", len(advisories))
	}
}

func TestInsecureProtocolDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// FTP (21) with 20 packets (above threshold)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 21, 6, 2000, 20)
	rb.Insert([]model.Flow{f1})

	// Telnet (23) where the server is the source port
	f2 := makeFlow("192.168.1.2", "10.0.0.1", 23, 12345, 6, 1500, 15)
	rb.Insert([]model.Flow{f2})

	detector := InsecureProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advisories))
	}

	foundFTP := false
	foundTelnet := false
	for _, a := range advisories {
		if a.Severity != WARNING {
			t.Errorf("expected WARNING severity, got %v", a.Severity)
		}
		if a.Title == "Insecure Protocol Usage: 192.168.1.1 (FTP)" {
			foundFTP = true
		} else if a.Title == "Insecure Protocol Usage: 192.168.1.2 (Telnet)" {
			foundTelnet = true
		} else {
			t.Errorf("unexpected title: %s", a.Title)
		}
	}

	if !foundFTP {
		t.Error("missing FTP advisory")
	}
	if !foundTelnet {
		t.Error("missing Telnet advisory")
	}
}

func TestInsecureProtocolDetector_MultipleClients(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// HTTP (80) with multiple clients
	flows := make([]model.Flow, 0, 5)
	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("10.0.0.%d", i+1)
		f := makeFlow(src, "192.168.1.5", uint16(10000+i), 80, 6, 1000, 10)
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := InsecureProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Insecure Protocol Usage: 192.168.1.5 (HTTP)"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}
