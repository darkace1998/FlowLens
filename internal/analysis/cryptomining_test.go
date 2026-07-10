package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestCryptominingDetector(t *testing.T) {
	now := time.Now()
	cfg := config.AnalysisConfig{
		QueryWindow: 5 * time.Minute,
	}

	tests := []struct {
		name       string
		flows      []model.Flow
		wantAlerts int
	}{
		{
			name: "No cryptomining traffic",
			flows: []model.Flow{
				{
					SrcAddr:  net.ParseIP("192.168.1.10"),
					DstAddr:  net.ParseIP("8.8.8.8"),
					DstPort:  53,
					Protocol: 17,
					Bytes:    500,
					Packets:  2,
					Timestamp: now,
				},
				{
					SrcAddr:  net.ParseIP("192.168.1.10"),
					DstAddr:  net.ParseIP("9.9.9.9"),
					DstPort:  443,
					Protocol: 6,
					Bytes:    2000,
					Packets:  10,
					Timestamp: now,
				},
			},
			wantAlerts: 0,
		},
		{
			name: "Cryptomining traffic on port 3333",
			flows: []model.Flow{
				{
					SrcAddr:  net.ParseIP("192.168.1.50"),
					DstAddr:  net.ParseIP("203.0.113.1"),
					DstPort:  3333,
					Protocol: 6,
					Bytes:    100000,
					Packets:  150,
					Timestamp: now,
				},
			},
			wantAlerts: 1,
		},
		{
			name: "Cryptomining traffic on port 14444 (UDP)",
			flows: []model.Flow{
				{
					SrcAddr:  net.ParseIP("10.0.0.5"),
					DstAddr:  net.ParseIP("198.51.100.50"),
					DstPort:  14444,
					Protocol: 17,
					Bytes:    800000, // Should trigger CRITICAL
					Packets:  500,
					Timestamp: now,
				},
			},
			wantAlerts: 1,
		},
		{
			name: "Multiple distinct cryptomining targets",
			flows: []model.Flow{
				{
					SrcAddr:  net.ParseIP("10.0.0.10"),
					DstAddr:  net.ParseIP("198.51.100.1"),
					DstPort:  4444,
					Protocol: 6,
					Bytes:    5000,
					Packets:  50,
					Timestamp: now,
				},
				{
					SrcAddr:  net.ParseIP("10.0.0.10"),
					DstAddr:  net.ParseIP("198.51.100.2"),
					DstPort:  5555,
					Protocol: 6,
					Bytes:    5000,
					Packets:  50,
					Timestamp: now,
				},
				{
					SrcAddr:  net.ParseIP("10.0.0.10"),
					DstAddr:  net.ParseIP("198.51.100.3"),
					DstPort:  7777,
					Protocol: 6,
					Bytes:    5000,
					Packets:  50,
					Timestamp: now,
				},
				{
					SrcAddr:  net.ParseIP("10.0.0.10"),
					DstAddr:  net.ParseIP("198.51.100.4"),
					DstPort:  8333,
					Protocol: 6,
					Bytes:    5000,
					Packets:  50,
					Timestamp: now,
				},
			},
			wantAlerts: 1, // One alert for the source IP, but should be CRITICAL due to >3 targets
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewRingBuffer(100)
			store.Insert(tt.flows)

			detector := CryptominingDetector{}
			advisories := detector.Analyze(store, cfg)

			if len(advisories) != tt.wantAlerts {
				t.Errorf("Analyze() returned %d advisories, want %d", len(advisories), tt.wantAlerts)
			}

			if len(advisories) > 0 {
				if tt.name == "Cryptomining traffic on port 14444 (UDP)" {
					if advisories[0].Severity != CRITICAL {
						t.Errorf("Expected CRITICAL severity for large byte transfer, got %s", advisories[0].Severity)
					}
				}
				if tt.name == "Multiple distinct cryptomining targets" {
					if advisories[0].Severity != CRITICAL {
						t.Errorf("Expected CRITICAL severity for multiple targets, got %s", advisories[0].Severity)
					}
				}
			}
		})
	}
}
