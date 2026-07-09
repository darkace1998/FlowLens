package analysis

import (
	"fmt"
	"testing"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestSuspiciousFlagsDetector_Empty(t *testing.T) {
	rb := storage.NewRingBuffer(100)
	detector := SuspiciousFlagsDetector{}

	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("empty store should produce 0 advisories, got %d", len(advisories))
	}
}

func TestSuspiciousFlagsDetector_StorageError(t *testing.T) {
	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())

	if advisories != nil {
		t.Errorf("expected nil advisories on storage error, got %v", advisories)
	}
}

func TestSuspiciousFlagsDetector_NormalTraffic(t *testing.T) {
	rb := storage.NewRingBuffer(100)

	// SYN (0x02)
	f1 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 100, 1)
	f1.TCPFlags = 0x02
	rb.Insert([]model.Flow{f1})

	// SYN-ACK (0x12)
	f2 := makeFlow("192.168.1.1", "10.0.0.1", 80, 12345, 6, 100, 1)
	f2.TCPFlags = 0x12
	rb.Insert([]model.Flow{f2})

	// ACK (0x10)
	f3 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 100, 1)
	f3.TCPFlags = 0x10
	rb.Insert([]model.Flow{f3})

	// FIN-ACK (0x11)
	f4 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 100, 1)
	f4.TCPFlags = 0x11
	rb.Insert([]model.Flow{f4})

	// UDP
	f5 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 53, 17, 100, 1)
	rb.Insert([]model.Flow{f5})

	// Missing Flags (0x00) with Packets > 1 should be ignored
	f6 := makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6, 1000, 10)
	f6.TCPFlags = 0x00
	rb.Insert([]model.Flow{f6})

	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories for normal traffic, got %d", len(advisories))
	}
}

func TestSuspiciousFlagsDetector_SynFin(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 10)
	// Create flows hitting 10 targets
	for i := 0; i < 10; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i+1)
		f := makeFlow("10.0.0.1", dst, 12345, 80, 6, 100, 1)
		f.TCPFlags = 0x03 // SYN-FIN
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != WARNING {
		t.Errorf("expected WARNING severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Suspicious TCP Flags (SYN-FIN): 10.0.0.1"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestSuspiciousFlagsDetector_XmasCritical(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 60)
	// Create flows hitting 60 targets (above 50 threshold for CRITICAL)
	for i := 0; i < 60; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i+1)
		f := makeFlow("10.0.0.2", dst, 12345, 80, 6, 100, 1)
		f.TCPFlags = 0x29 // FIN, PSH, URG
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	if advisories[0].Severity != CRITICAL {
		t.Errorf("expected CRITICAL severity, got %v", advisories[0].Severity)
	}

	expectedTitle := "Suspicious TCP Flags (XMAS): 10.0.0.2"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestSuspiciousFlagsDetector_Null(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 5)
	// Create flows hitting 5 targets
	for i := 0; i < 5; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i+1)
		f := makeFlow("10.0.0.5", dst, 12345, 80, 6, 100, 1)
		f.TCPFlags = 0x00 // NULL scan (flags=0, packets=1)
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	expectedTitle := "Suspicious TCP Flags (NULL): 10.0.0.5"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestSuspiciousFlagsDetector_FinOnly(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 5)
	// Create flows hitting 5 targets
	for i := 0; i < 5; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i+1)
		f := makeFlow("10.0.0.3", dst, 12345, 80, 6, 100, 1)
		f.TCPFlags = 0x01 // FIN only (no ACK)
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	expectedTitle := "Suspicious TCP Flags (FIN): 10.0.0.3"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}

func TestSuspiciousFlagsDetector_SynRst(t *testing.T) {
	rb := storage.NewRingBuffer(1000)

	flows := make([]model.Flow, 0, 5)
	// Create flows hitting 5 targets
	for i := 0; i < 5; i++ {
		dst := fmt.Sprintf("192.168.1.%d", i+1)
		f := makeFlow("10.0.0.4", dst, 12345, 80, 6, 100, 1)
		f.TCPFlags = 0x06 // SYN-RST
		flows = append(flows, f)
	}
	rb.Insert(flows)

	detector := SuspiciousFlagsDetector{}
	advisories := detector.Analyze(rb, defaultCfg())

	if len(advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(advisories))
	}

	expectedTitle := "Suspicious TCP Flags (SYN-RST): 10.0.0.4"
	if advisories[0].Title != expectedTitle {
		t.Errorf("expected title %q, got %q", expectedTitle, advisories[0].Title)
	}
}
