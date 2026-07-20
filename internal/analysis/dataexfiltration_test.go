package analysis

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func makeTestFlowExfiltration(src, dst string, bytes uint64) model.Flow {
	return model.Flow{
		SrcAddr:   net.ParseIP(src),
		DstAddr:   net.ParseIP(dst),
		Bytes:     bytes,
		Timestamp: time.Now(),
	}
}

func TestDataExfiltrationDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	advisories := DataExfiltrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_StorageError(t *testing.T) {
	advisories := DataExfiltrationDetector{}.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_UnderThreshold(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Private to Public, but under 500MB
	rb.Insert([]model.Flow{
		makeTestFlowExfiltration("192.168.1.100", "8.8.8.8", 100*1024*1024),
	})

	advisories := DataExfiltrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for traffic under threshold, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_PrivateToPrivate(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Private to Private, over 500MB, but should not trigger because destination is internal
	rb.Insert([]model.Flow{
		makeTestFlowExfiltration("192.168.1.100", "10.0.0.1", 600*1024*1024),
	})

	advisories := DataExfiltrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for internal traffic, got %d", len(advisories))
	}
}

func TestDataExfiltrationDetector_Warning(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Private to Public, over 500MB
	rb.Insert([]model.Flow{
		makeTestFlowExfiltration("192.168.1.100", "8.8.8.8", 600*1024*1024),
	})

	advisories := DataExfiltrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}
	expectedTitle := "Data Exfiltration: 192.168.1.100"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_Critical(t *testing.T) {
	rb := storage.NewRingBuffer(1000)
	// Private to Public, over 2.5GB
	rb.Insert([]model.Flow{
		makeTestFlowExfiltration("10.0.0.50", "1.1.1.1", 3000*1024*1024),
	})

	advisories := DataExfiltrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}
	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}
	expectedTitle := "Data Exfiltration: 10.0.0.50"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestDataExfiltrationDetector_TruncationAndSorting(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	// Add 12 hosts that exceed the 500MB threshold.
	for i := 1; i <= 12; i++ {
		rb.Insert([]model.Flow{
			makeTestFlowExfiltration(fmt.Sprintf("192.168.1.%d", i), "8.8.8.8", uint64(500*1024*1024+i*1024*1024)),
		})
	}

	advisories := DataExfiltrationDetector{}.Analyze(rb, defaultCfg())
	if len(advisories) != 10 {
		t.Fatalf("expected exactly 10 advisories (truncated from 12), got %d", len(advisories))
	}

	// Ensure sorted by highest bytes first.
	// 192.168.1.12 should be first, 192.168.1.11 second, etc.
	expectedTopTitle := "Data Exfiltration: 192.168.1.12"
	if advisories[0].Title != expectedTopTitle {
		t.Errorf("expected top advisory to be %q, got %q", expectedTopTitle, advisories[0].Title)
	}
}
