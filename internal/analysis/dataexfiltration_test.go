package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestDataExfiltrationDetector_Analyze(t *testing.T) {
	detector := DataExfiltrationDetector{}
	cfg := config.AnalysisConfig{
		QueryWindow:             10 * time.Minute,
		ExfiltrationThresholdMB: 10, // 10 MB threshold
	}

	now := time.Now()

	privateIP1 := net.ParseIP("192.168.1.100")
	privateIP2 := net.ParseIP("10.0.0.5")
	publicIP1 := net.ParseIP("8.8.8.8")
	publicIP2 := net.ParseIP("1.1.1.1")

	thresholdBytes := uint64(10 * 1024 * 1024)

	tests := []struct {
		name       string
		flows      []model.Flow
		wantAlerts int
		wantSev    Severity
	}{
		{
			name: "Internal to Internal traffic - no alert",
			flows: []model.Flow{
				{
					SrcAddr:   privateIP1,
					DstAddr:   privateIP2,
					Bytes:     thresholdBytes + 1000,
					Timestamp: now,
				},
			},
			wantAlerts: 0,
		},
		{
			name: "Small Internal to External traffic - no alert",
			flows: []model.Flow{
				{
					SrcAddr:   privateIP1,
					DstAddr:   publicIP1,
					Bytes:     thresholdBytes - 1000,
					Timestamp: now,
				},
			},
			wantAlerts: 0,
		},
		{
			name: "Large Internal to External traffic - WARNING",
			flows: []model.Flow{
				{
					SrcAddr:   privateIP1,
					DstAddr:   publicIP1,
					Bytes:     thresholdBytes + 1000,
					Timestamp: now,
				},
			},
			wantAlerts: 1,
			wantSev:    WARNING,
		},
		{
			name: "Very Large Internal to External traffic - CRITICAL",
			flows: []model.Flow{
				{
					SrcAddr:   privateIP1,
					DstAddr:   publicIP1,
					Bytes:     thresholdBytes * 6,
					Timestamp: now,
				},
			},
			wantAlerts: 1,
			wantSev:    CRITICAL,
		},
		{
			name: "Multiple flows combining to exceed threshold - WARNING",
			flows: []model.Flow{
				{
					SrcAddr:   privateIP1,
					DstAddr:   publicIP1,
					Bytes:     thresholdBytes / 2,
					Timestamp: now,
				},
				{
					SrcAddr:   privateIP1,
					DstAddr:   publicIP2,
					Bytes:     (thresholdBytes / 2) + 1000,
					Timestamp: now,
				},
			},
			wantAlerts: 1,
			wantSev:    WARNING,
		},
		{
			name: "Public to Public traffic - no alert",
			flows: []model.Flow{
				{
					SrcAddr:   net.ParseIP("8.8.4.4"),
					DstAddr:   publicIP1,
					Bytes:     thresholdBytes + 1000,
					Timestamp: now,
				},
			},
			wantAlerts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := storage.NewRingBuffer(1000)
			if len(tt.flows) > 0 {
				_ = rb.Insert(tt.flows)
			}

			advisories := detector.Analyze(rb, cfg)

			if len(advisories) != tt.wantAlerts {
				t.Errorf("got %d advisories, want %d", len(advisories), tt.wantAlerts)
			}

			if tt.wantAlerts > 0 && len(advisories) > 0 {
				if advisories[0].Severity != tt.wantSev {
					t.Errorf("got severity %s, want %s", advisories[0].Severity, tt.wantSev)
				}
			}
		})
	}
}

func TestDataExfiltrationDetector_StorageError(t *testing.T) {
	detector := DataExfiltrationDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())
	if advisories != nil {
		t.Errorf("expected nil on storage error, got %v", advisories)
	}
}

func TestDataExfiltrationDetector_EmptyStorage(t *testing.T) {
	detector := DataExfiltrationDetector{}
	rb := storage.NewRingBuffer(10)
	advisories := detector.Analyze(rb, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on empty storage, got %v", advisories)
	}
}
