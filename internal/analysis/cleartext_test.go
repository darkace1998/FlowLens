package analysis

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestCleartextProtocolDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for empty storage, got %d", len(advisories))
	}
}

func TestCleartextProtocolDetector_ValidTelnet(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Valid Telnet connection (port 23, TCP)
	f := makeFlow("10.0.0.5", "10.0.0.1", 12345, 23, 6, 5000, 10)
	rb.Insert([]model.Flow{f})

	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	a := advisories[0]
	if a.Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", a.Severity)
	}
	if a.Title != "Cleartext Protocol (Telnet): 10.0.0.1" {
		t.Errorf("unexpected title: %s", a.Title)
	}
}

func TestCleartextProtocolDetector_ValidTFTP(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Valid TFTP connection (port 69, UDP)
	f := makeFlow("10.0.0.5", "10.0.0.1", 12345, 69, 17, 5000, 10)
	rb.Insert([]model.Flow{f})

	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	a := advisories[0]
	if a.Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", a.Severity)
	}
	if a.Title != "Cleartext Protocol (TFTP): 10.0.0.1" {
		t.Errorf("unexpected title: %s", a.Title)
	}
}

func TestCleartextProtocolDetector_ValidSrcPort(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Server responds from cleartext port (e.g., FTP data/control return)
	f := makeFlow("10.0.0.1", "10.0.0.5", 21, 12345, 6, 5000, 10)
	rb.Insert([]model.Flow{f})

	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	a := advisories[0]
	if a.Title != "Cleartext Protocol (FTP): 10.0.0.1" {
		t.Errorf("unexpected title: %s", a.Title)
	}
}

func TestCleartextProtocolDetector_ShortFlowFiltered(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Telnet connection with only 2 packets (e.g., scan probe)
	f := makeFlow("10.0.0.5", "10.0.0.1", 12345, 23, 6, 120, 2)
	rb.Insert([]model.Flow{f})

	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories due to short flow, got %d", len(advisories))
	}
}

func TestCleartextProtocolDetector_WrongProtocol(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Port 23 but UDP instead of TCP
	f := makeFlow("10.0.0.5", "10.0.0.1", 12345, 23, 17, 5000, 10)
	rb.Insert([]model.Flow{f})

	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories due to wrong L4 protocol, got %d", len(advisories))
	}
}

func TestCleartextProtocolDetector_NonCleartextPort(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// SSH (encrypted)
	f := makeFlow("10.0.0.5", "10.0.0.1", 12345, 22, 6, 5000, 10)
	rb.Insert([]model.Flow{f})

	advisories := CleartextProtocolDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for non-cleartext port, got %d", len(advisories))
	}
}

func TestCleartextProtocolDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := CleartextProtocolDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories, got %v", advisories)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "CleartextProtocolDetector: failed to query flows:") {
		t.Errorf("expected log to contain error message, got %q", logOutput)
	}
}

func TestCleartextProtocolDetector_Name(t *testing.T) {
	name := CleartextProtocolDetector{}.Name()
	if name != "Cleartext Protocol Detector" {
		t.Errorf("unexpected name: %s", name)
	}
}
