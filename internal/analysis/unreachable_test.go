package analysis

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestUnreachableDetector_Name(t *testing.T) {
	d := UnreachableDetector{}
	if d.Name() != "Unreachable Host Detector" {
		t.Errorf("unexpected name: %s", d.Name())
	}
}

func TestUnreachableDetector_StoreError(t *testing.T) {
	t.Run("StorageError", func(t *testing.T) {
		var buf bytes.Buffer
		logging.Default().SetOutput(&buf)
		defer logging.Default().SetOutput(os.Stderr)

		d := UnreachableDetector{}
		adv := d.Analyze(mockErrorStorage{}, defaultCfg())
		if adv != nil {
			t.Errorf("expected nil advisories on error, got %v", adv)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "UnreachableDetector: failed to query flows") {
			t.Errorf("expected error log, got: %s", logOutput)
		}
	})
}

func TestUnreachableDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	adv := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(adv) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(adv))
	}
}

func TestUnreachableDetector_IgnoreICMP(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	for i := 0; i < 30; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", 0, 0, 1, 60, 1),
		})
	}
	adv := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(adv) != 0 {
		t.Errorf("expected 0 advisories for ICMP flows, got %d", len(adv))
	}
}

func TestUnreachableDetector_BelowThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	for i := 0; i < 10; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", 1000, 80, 6, 60, 1),
		})
	}
	adv := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(adv) != 0 {
		t.Errorf("expected 0 advisories for < 20 tiny flows, got %d", len(adv))
	}
}

func TestUnreachableDetector_BelowPercentage(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	for i := 0; i < 20; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", 1000, 80, 6, 60, 1),
		})
	}
	for i := 0; i < 20; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", 1000, 80, 6, 5000, 10),
		})
	}
	adv := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(adv) != 0 {
		t.Errorf("expected 0 advisories for < 70%% tiny flows, got %d", len(adv))
	}
}

func TestUnreachableDetector_TruncateResults(t *testing.T) {
	rb := storage.NewRingBuffer(2000)
	for d := 0; d < 12; d++ {
		dstIP := fmt.Sprintf("192.168.1.%d", d)
		for i := 0; i < 20+d; i++ {
			rb.Insert([]model.Flow{
				makeFlow(fmt.Sprintf("10.0.1.%d", i), dstIP, 1000, 80, 6, 60, 1),
			})
		}
	}
	adv := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(adv) != 10 {
		t.Fatalf("expected 10 advisories (truncated from 12), got %d", len(adv))
	}
	if adv[0].Title != "Unreachable: 192.168.1.11:80" {
		t.Errorf("expected highest flow count to be first, got %s", adv[0].Title)
	}
}

func TestUnreachableDetector_WarningSeverity(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	for i := 0; i < 25; i++ {
		rb.Insert([]model.Flow{
			makeFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80, 6, 60, 1),
		})
	}
	adv := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(adv) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(adv))
	}
	if adv[0].Severity != WARNING {
		t.Errorf("expected WARNING severity for single source, got %v", adv[0].Severity)
	}
	action := unreachableAction(WARNING)
	if action != "Check service availability — many failed connection attempts detected." {
		t.Errorf("unexpected action string: %s", action)
	}
}

func TestUnreachableDetector_HealthyService(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Normal flows — large bytes, not tiny.
	for i := 0; i < 50; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.1", uint16(1000+i), 80, 6, 5000, 50),
		})
	}

	advisories := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("healthy service should produce 0 advisories, got %d", len(advisories))
	}
}

func TestUnreachableDetector_DownService(t *testing.T) {
	rb := storage.NewRingBuffer(10000)
	// Many tiny flows from multiple sources → service appears down.
	for i := 0; i < 30; i++ {
		rb.Insert([]model.Flow{
			makeFlow(fmt.Sprintf("10.0.1.%d", i), "192.168.1.100", uint16(1000+i), 443, 6, 60, 1),
		})
	}

	advisories := UnreachableDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory for unreachable service, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("30 tiny flows from 30 sources should be CRITICAL, got %s", advisories[0].Severity)
	}
}
