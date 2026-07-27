package analysis

import (
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestCleartextProtocolDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := CleartextProtocolDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestCleartextProtocolDetector_StorageError(t *testing.T) {
	detector := CleartextProtocolDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestCleartextProtocolDetector_EncryptedTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// HTTPS traffic
	rb.Insert([]model.Flow{
		makeFlow("10.0.0.1", "192.168.1.1", 12345, 443, 6, 1000, 10),
	})

	// SSH traffic
	rb.Insert([]model.Flow{
		makeFlow("10.0.0.1", "192.168.1.2", 12345, 22, 6, 1000, 10),
	})

	detector := CleartextProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for encrypted traffic, got %d", len(advisories))
	}
}

func TestCleartextProtocolDetector_CleartextTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Telnet traffic
	rb.Insert([]model.Flow{
		makeFlow("10.0.0.1", "192.168.1.1", 12345, 23, 6, 1000, 10),
	})

	detector := CleartextProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for cleartext traffic, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Cleartext Protocol Detected: 10.0.0.1 → 192.168.1.1 (Telnet)"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestCleartextProtocolDetector_MultipleCleartext(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// FTP and HTTP
	rb.Insert([]model.Flow{
		makeFlow("10.0.0.1", "192.168.1.1", 12345, 21, 6, 500, 5),
		makeFlow("10.0.0.2", "192.168.1.2", 12345, 80, 6, 1000, 10),
	})

	detector := CleartextProtocolDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories for cleartext traffic, got %d", len(advisories))
	}

	foundFTP := false
	foundHTTP := false

	for _, adv := range advisories {
		if adv.Title == "Cleartext Protocol Detected: 10.0.0.1 → 192.168.1.1 (FTP)" {
			foundFTP = true
		} else if adv.Title == "Cleartext Protocol Detected: 10.0.0.2 → 192.168.1.2 (HTTP)" {
			foundHTTP = true
		}
	}

	if !foundFTP {
		t.Errorf("missing FTP advisory")
	}
	if !foundHTTP {
		t.Errorf("missing HTTP advisory")
	}
}
