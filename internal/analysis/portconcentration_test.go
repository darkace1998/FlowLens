package analysis

import (
	"bytes"
	"fmt"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"os"
	"strings"
	"testing"
)

// --- Port Concentration Detector tests ---

func TestPortConcentrationDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationDetector_Normal(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Few sources to one port — normal.
	for i := 0; i < 5; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", uint16(1000+i), 80, 6, 5000, 50),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("5 sources to one port should produce 0 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationDetector_HighConcentration(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	// 25 unique sources all hitting the same port.
	for i := 0; i < 25; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", uint16(50000+i), 443, 6, 5000, 50),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for high port concentration, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("25 sources should be WARNING, got %s", advisories[0].Severity)
	}
}

func TestPortConcentrationDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(100000)
	// 60+ unique sources (>= 3x threshold of 20) → CRITICAL.
	for i := 0; i < 65; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.%d.%d", i/256, i%256), "192.168.1.1", uint16(50000+i), 22, 6, 100, 1),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("65 sources (>= 3x20) should be CRITICAL, got %s", advisories[0].Severity)
	}
}

func TestPortConcentrationDetector_Name(t *testing.T) {
	name := PortConcentrationDetector{}.Name()
	expected := "Port Concentration Detector"
	if name != expected {
		t.Errorf("expected name %q, got %q", expected, name)
	}
}

func TestPortConcentrationDetector_StorageError(t *testing.T) {
	var buf bytes.Buffer
	logging.Default().SetOutput(&buf)
	defer logging.Default().SetOutput(os.Stderr)

	advisories := PortConcentrationDetector{}.Analyze(mockErrorStorage{}, defaultCfg())

	logOutput := buf.String()

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}

	if !strings.Contains(logOutput, "failed to query") {
		t.Errorf("expected log message not found, got: %q", logOutput)
	}
}

func TestPortConcentrationDetector_IgnoresNonTCPUDP(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Create ICMP flows (protocol 1) with high concentration
	for i := 0; i < 25; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", 0, 0, 1, 5000, 50),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("ICMP flows should not trigger port concentration detection, got %d advisories", len(advisories))
	}
}

func TestPortConcentrationDetector_LimitsToTop10(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Create 15 distinct ports, each with 25 distinct sources (enough to trigger WARNING)
	for portOffset := 0; portOffset < 15; portOffset++ {
		for i := 0; i < 25; i++ {
			rb.Insert([]model.Flow{
				makeFlow(fmt.Sprintf("10.0.%d.%d", portOffset, i), "192.168.1.1", uint16(50000+portOffset), 443, 6, 5000, 50),
			})
		}
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) > 10 {
		t.Errorf("expected at most 10 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationAction_Critical(t *testing.T) {
	action := portConcentrationAction(CRITICAL)
	if action == "" {
		t.Errorf("expected non-empty action string for CRITICAL severity")
	}
}

func TestPortConcentrationAction_Warning(t *testing.T) {
	action := portConcentrationAction(WARNING)
	if action == "" {
		t.Errorf("expected non-empty action string for WARNING severity")
	}
}

func TestPortConcentrationDetector_EmptyFlows(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationDetector_ExistingPortStat(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Create multiple flows to the same port to trigger the `!ok` else branch
	rb.Insert([]model.Flow{
		makeFlow("10.0.1.1", "192.168.1.1", 1000, 80, 6, 5000, 50),
		makeFlow("10.0.1.2", "192.168.1.1", 1001, 80, 6, 5000, 50),
		makeFlow("10.0.1.3", "192.168.1.1", 1002, 80, 6, 5000, 50),
	})

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories, got %d", len(advisories))
	}
}

func TestPortConcentrationDetector_SortResults(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Create two ports, one with 25 sources, one with 30 sources.
	// The 30 sources should be first in the results.
	for i := 0; i < 25; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", 50000, 1000, 6, 5000, 50),
		})
	}
	for i := 0; i < 30; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.2.%d", i), "192.168.1.1", 50000, 2000, 6, 5000, 50),
		})
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(advisories))
	}

	// Assuming the titles indicate the port
	if advisories[0].Title != "Port Concentration: 192.168.1.1:2000" {
		t.Errorf("expected highest concentration first, got %s", advisories[0].Title)
	}
}

func TestPortConcentrationDetector_MoreThan10Ports(t *testing.T) {
	rb := storage.NewRingBuffer(100000)

	// Need 11 ports to trigger truncation. Each needs >= 20 sources to pass threshold.
	for port := 0; port < 12; port++ {
		for i := 0; i < 25; i++ {
			rb.Insert([]model.Flow{
				makeFlow(fmt.Sprintf("10.0.%d.%d", port, i), "192.168.1.1", 50000, uint16(1000+port), 6, 5000, 50),
			})
		}
	}

	advisories := PortConcentrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 10 {
		t.Fatalf("expected exactly 10 advisories due to limit, got %d", len(advisories))
	}
}
