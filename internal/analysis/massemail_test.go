package analysis

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestMassEmailDetector(t *testing.T) {
	now := time.Now()
	cfg := config.AnalysisConfig{QueryWindow: 5 * time.Minute}
	detector := MassEmailDetector{}

	tests := []struct {
		name          string
		flows         []model.Flow
		wantCount     int
		checkSeverity Severity
	}{
		{
			name: "Normal traffic - no mass email",
			flows: []model.Flow{
				{
					Timestamp: now,
					SrcAddr:   net.ParseIP("192.168.1.10"),
					DstAddr:   net.ParseIP("10.0.0.1"),
					DstPort:   25,
					Protocol:  6,
					Bytes:     500,
					Packets:   10,
				},
			},
			wantCount: 0,
		},
		{
			name: "Below threshold (19 distinct targets)",
			flows: func() []model.Flow {
				flows := make([]model.Flow, 0, 19)
				for i := 1; i <= 19; i++ {
					flows = append(flows, model.Flow{
						Timestamp: now,
						SrcAddr:   net.ParseIP("192.168.1.10"),
						DstAddr:   net.ParseIP(fmt.Sprintf("10.0.0.%d", i)),
						DstPort:   25,
						Protocol:  6,
						Bytes:     500,
						Packets:   10,
					})
				}
				return flows
			}(),
			wantCount: 0,
		},
		{
			name: "Warning threshold (20 distinct targets)",
			flows: func() []model.Flow {
				flows := make([]model.Flow, 0, 20)
				for i := 1; i <= 20; i++ {
					flows = append(flows, model.Flow{
						Timestamp: now,
						SrcAddr:   net.ParseIP("192.168.1.10"),
						DstAddr:   net.ParseIP(fmt.Sprintf("10.0.0.%d", i)),
						DstPort:   587,
						Protocol:  6,
						Bytes:     500,
						Packets:   10,
					})
				}
				return flows
			}(),
			wantCount:     1,
			checkSeverity: WARNING,
		},
		{
			name: "Critical threshold (60 distinct targets)",
			flows: func() []model.Flow {
				flows := make([]model.Flow, 0, 60)
				for i := 1; i <= 60; i++ {
					flows = append(flows, model.Flow{
						Timestamp: now,
						SrcAddr:   net.ParseIP("192.168.1.10"),
						DstAddr:   net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250)),
						DstPort:   465,
						Protocol:  6,
						Bytes:     500,
						Packets:   10,
					})
				}
				return flows
			}(),
			wantCount:     1,
			checkSeverity: CRITICAL,
		},
		{
			name: "Non-TCP traffic ignored",
			flows: func() []model.Flow {
				flows := make([]model.Flow, 0, 25)
				for i := 1; i <= 25; i++ {
					flows = append(flows, model.Flow{
						Timestamp: now,
						SrcAddr:   net.ParseIP("192.168.1.10"),
						DstAddr:   net.ParseIP(fmt.Sprintf("10.0.0.%d", i)),
						DstPort:   25,
						Protocol:  17, // UDP
						Bytes:     500,
						Packets:   10,
					})
				}
				return flows
			}(),
			wantCount: 0,
		},
		{
			name: "Non-SMTP ports ignored",
			flows: func() []model.Flow {
				flows := make([]model.Flow, 0, 25)
				for i := 1; i <= 25; i++ {
					flows = append(flows, model.Flow{
						Timestamp: now,
						SrcAddr:   net.ParseIP("192.168.1.10"),
						DstAddr:   net.ParseIP(fmt.Sprintf("10.0.0.%d", i)),
						DstPort:   80, // HTTP
						Protocol:  6,
						Bytes:     500,
						Packets:   10,
					})
				}
				return flows
			}(),
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewRingBuffer(1000)
			err := store.Insert(tt.flows)
			if err != nil {
				t.Fatalf("Failed to insert flows: %v", err)
			}

			advisories := detector.Analyze(store, cfg)
			if len(advisories) != tt.wantCount {
				t.Errorf("Analyze() returned %d advisories, want %d", len(advisories), tt.wantCount)
			}
			if tt.wantCount > 0 && len(advisories) > 0 {
				if advisories[0].Severity != tt.checkSeverity {
					t.Errorf("Advisory severity = %s, want %s", advisories[0].Severity, tt.checkSeverity)
				}
			}
		})
	}
}
