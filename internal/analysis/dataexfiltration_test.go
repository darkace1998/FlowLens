package analysis

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestDataExfiltrationDetector_Analyze(t *testing.T) {
	d := DataExfiltrationDetector{}

	if d.Name() != "Data Exfiltration Detector" {
		t.Errorf("expected Name() to be 'Data Exfiltration Detector', got %s", d.Name())
	}

	cfg := defaultCfg()
	cfg.ExfiltrationThresholdMB = 100 // Test with 100MB threshold
	thresholdBytes := uint64(100) * 1024 * 1024

	// Storage error test
	adv := d.Analyze(&mockErrorStorage{}, cfg)
	if adv != nil {
		t.Errorf("expected nil advisories on storage error, got %d", len(adv))
	}

	tests := []struct {
		name             string
		flows            []model.Flow
		expectedAdvs     int
		expectedSeverity Severity
	}{
		{
			name: "No large transfers",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.100"),
					DstAddr:   net.ParseIP("8.8.8.8"),
					Bytes:     thresholdBytes / 2, // 50MB
				},
			},
			expectedAdvs: 0,
		},
		{
			name: "Large transfer but internal to internal",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.5"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Bytes:     thresholdBytes * 2, // 200MB
				},
			},
			expectedAdvs: 0,
		},
		{
			name: "Large inbound transfer (public to private)",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("8.8.8.8"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Bytes:     thresholdBytes * 2, // 200MB
				},
			},
			expectedAdvs: 0,
		},
		{
			name: "Large outbound transfer (Warning)",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.50"),
					DstAddr:   net.ParseIP("93.184.216.34"), // example.com
					Bytes:     thresholdBytes * 2,           // 200MB (2x threshold)
				},
			},
			expectedAdvs:     1,
			expectedSeverity: WARNING,
		},
		{
			name: "Massive outbound transfer (Critical)",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("172.16.5.10"),
					DstAddr:   net.ParseIP("203.0.113.5"),
					Bytes:     thresholdBytes * 6, // 600MB (6x threshold, > 5x)
				},
			},
			expectedAdvs:     1,
			expectedSeverity: CRITICAL,
		},
		{
			name: "Aggregated large outbound transfer",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.10"),
					DstAddr:   net.ParseIP("198.51.100.1"),
					Bytes:     thresholdBytes / 2, // 50MB
				},
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.10"),
					DstAddr:   net.ParseIP("198.51.100.1"),
					Bytes:     (thresholdBytes / 2) + 1000, // 50MB + a bit
				},
			},
			expectedAdvs:     1,
			expectedSeverity: WARNING,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewRingBuffer(1000)
			err := store.Insert(tt.flows)
			if err != nil {
				t.Fatalf("failed to insert flows: %v", err)
			}

			advs := d.Analyze(store, cfg)
			if len(advs) != tt.expectedAdvs {
				t.Fatalf("expected %d advisories, got %d", tt.expectedAdvs, len(advs))
			}

			if len(advs) > 0 {
				if advs[0].Severity != tt.expectedSeverity {
					t.Errorf("expected severity %v, got %v", tt.expectedSeverity, advs[0].Severity)
				}
				if !strings.Contains(advs[0].Title, "Data Exfiltration") {
					t.Errorf("expected title to contain 'Data Exfiltration', got %s", advs[0].Title)
				}
			}
		})
	}
}
