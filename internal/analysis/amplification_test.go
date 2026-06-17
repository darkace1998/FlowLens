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

func TestAmplificationDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for empty storage, got %d", len(advisories))
	}
}

func TestAmplificationDetector_BelowThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Add 10 sources sending UDP from port 53 (DNS), but small bytes
	for i := 0; i < 10; i++ {
		srcIP := "8.8.8.8"
		if i > 0 {
			srcIP = "8.8.4.4"
		}
		f := makeFlow(srcIP, "10.0.0.1", 53, 12345, 17, 1000, 1)
		f.SrcAddr[3] = byte(i + 1) // Unique source IPs
		rb.Insert([]model.Flow{f})
	}

	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories (bytes below threshold), got %d", len(advisories))
	}
}

func TestAmplificationDetector_FewSources(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Add high bytes but only from 3 sources
	for i := 0; i < 3; i++ {
		f := makeFlow("8.8.8.8", "10.0.0.1", 53, 12345, 17, amplificationMinBytes, 1)
		f.SrcAddr[3] = byte(i + 1) // Unique source IPs
		rb.Insert([]model.Flow{f})
	}

	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories (sources < 5), got %d", len(advisories))
	}
}

func TestAmplificationDetector_HighVolume(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Add 5 sources sending large amount of UDP from port 53 (DNS)
	for i := 0; i < 5; i++ {
		f := makeFlow("8.8.8.8", "10.0.0.1", 53, 12345, 17, amplificationMinBytes*3, 10)
		f.SrcAddr[3] = byte(i + 1) // Unique source IPs
		rb.Insert([]model.Flow{f})
	}

	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	a := advisories[0]
	if a.Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", a.Severity)
	}
	if a.Title != "Amplification Attack: 10.0.0.1 (DNS)" {
		t.Errorf("unexpected title: %s", a.Title)
	}
}

func TestAmplificationDetector_WarningVolume(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Add 5 sources sending large amount of UDP from port 123 (NTP)
	for i := 0; i < 5; i++ {
		f := makeFlow("1.1.1.1", "10.0.0.2", 123, 54321, 17, amplificationMinBytes/2, 5) // Total > amplificationMinBytes, but < *10
		f.SrcAddr[3] = byte(i + 1)                                                       // Unique source IPs
		rb.Insert([]model.Flow{f})
	}

	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	a := advisories[0]
	if a.Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", a.Severity)
	}
	if a.Title != "Amplification Attack: 10.0.0.2 (NTP)" {
		t.Errorf("unexpected title: %s", a.Title)
	}
}

func TestAmplificationDetector_NotUDP(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Add 5 sources sending large amount of TCP from port 53 (DNS)
	for i := 0; i < 5; i++ {
		f := makeFlow("8.8.8.8", "10.0.0.1", 53, 12345, 6, amplificationMinBytes*3, 10) // TCP
		f.SrcAddr[3] = byte(i + 1)                                                      // Unique source IPs
		rb.Insert([]model.Flow{f})
	}

	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories (not UDP), got %d", len(advisories))
	}
}

func TestAmplificationDetector_NotAmpPort(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// Add 5 sources sending large amount of UDP from port 443 (HTTPS)
	for i := 0; i < 5; i++ {
		f := makeFlow("8.8.8.8", "10.0.0.1", 443, 12345, 17, amplificationMinBytes*3, 10) // HTTPS UDP
		f.SrcAddr[3] = byte(i + 1)                                                        // Unique source IPs
		rb.Insert([]model.Flow{f})
	}

	advisories := AmplificationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories (not amplification port), got %d", len(advisories))
	}
}

func TestAmplificationDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := AmplificationDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil advisories, got %v", advisories)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "AmplificationDetector: failed to query recent flows:") {
		t.Errorf("expected log to contain \"AmplificationDetector: failed to query recent flows:\", got %q", logOutput)
	}
}

func TestAmplificationDetector_Name(t *testing.T) {
	name := AmplificationDetector{}.Name()
	if name != "Amplification Attack Detector" {
		t.Errorf("unexpected name: %s", name)
	}
}
