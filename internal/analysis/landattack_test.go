package analysis

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestLandAttackDetector(t *testing.T) {
	tests := []struct {
		name    string
		flows   []model.Flow
		want    int
		wantSev Severity
	}{
		{
			name:  "No Flows",
			flows: []model.Flow{},
			want:  0,
		},
		{
			name: "Normal Flow",
			flows: []model.Flow{
				{
					SrcAddr:   net.ParseIP("192.168.1.5"),
					DstAddr:   net.ParseIP("192.168.1.10"),
					Timestamp: time.Now(), Packets: 10,
					Bytes: 1000,
				},
			},
			want: 0,
		},
		{
			name: "Loopback Flow",
			flows: []model.Flow{
				{
					SrcAddr:   net.ParseIP("127.0.0.1"),
					DstAddr:   net.ParseIP("127.0.0.1"),
					Timestamp: time.Now(), Packets: 50,
					Bytes: 5000,
				},
			},
			want: 0,
		},
		{
			name: "LAND Attack Flow",
			flows: []model.Flow{
				{
					SrcAddr:   net.ParseIP("10.0.0.5"),
					DstAddr:   net.ParseIP("10.0.0.5"),
					Timestamp: time.Now(), Packets: 100,
					Bytes: 6000,
				},
			},
			want:    1,
			wantSev: CRITICAL,
		},
		{
			name: "Multiple LAND Attack Packets",
			flows: []model.Flow{
				{
					SrcAddr:   net.ParseIP("192.168.1.50"),
					DstAddr:   net.ParseIP("192.168.1.50"),
					Timestamp: time.Now(), Packets: 10,
					Bytes: 600,
				},
				{
					SrcAddr:   net.ParseIP("192.168.1.50"),
					DstAddr:   net.ParseIP("192.168.1.50"),
					Timestamp: time.Now(), Packets: 20,
					Bytes: 1200,
				},
			},
			want:    1,
			wantSev: CRITICAL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewRingBuffer(100)
			if len(tt.flows) > 0 {
				_ = store.Insert(tt.flows)
			}

			detector := LandAttackDetector{}
			cfg := config.AnalysisConfig{QueryWindow: time.Hour}

			got := detector.Analyze(store, cfg)

			if len(got) != tt.want {
				t.Fatalf("Analyze() returned %d advisories; want %d", len(got), tt.want)
			}

			if tt.want > 0 {
				if got[0].Severity != tt.wantSev {
					t.Errorf("Analyze() severity = %v; want %v", got[0].Severity, tt.wantSev)
				}
				if !strings.Contains(got[0].Title, "LAND Attack Detected") {
					t.Errorf("Analyze() title = %s; want to contain 'LAND Attack Detected'", got[0].Title)
				}
			}
		})
	}
}
