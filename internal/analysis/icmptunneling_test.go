package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestICMPTunnelingDetector(t *testing.T) {
	tests := []struct {
		name       string
		flows      []model.Flow
		wantAlerts int
		wantTitle  string
	}{
		{
			name: "normal ICMP traffic",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.100"),
					DstAddr:   net.ParseIP("8.8.8.8"),
					Protocol:  1, // ICMP
					Bytes:     1500,
					Packets:   20, // avg 75 bytes/packet
				},
			},
			wantAlerts: 0,
		},
		{
			name: "icmp tunneling detected IPv4",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.200"),
					DstAddr:   net.ParseIP("1.1.1.1"),
					Protocol:  1,
					Bytes:     600000, // > 100KB
					Packets:   2000,   // avg 300 bytes/packet
				},
			},
			wantAlerts: 1,
			wantTitle:  "ICMP Tunneling Activity: 192.168.1.200",
		},
		{
			name: "icmp tunneling detected IPv6",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("2001:db8::1"),
					DstAddr:   net.ParseIP("2001:db8::2"),
					Protocol:  58,     // ICMPv6
					Bytes:     150000, // > 100KB
					Packets:   500,    // avg 300 bytes/packet
				},
			},
			wantAlerts: 1,
			wantTitle:  "ICMP Tunneling Activity: 2001:db8::1",
		},
		{
			name: "high volume but small packets (not tunneling)",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.201"),
					DstAddr:   net.ParseIP("8.8.4.4"),
					Protocol:  1,
					Bytes:     150000, // > 100KB
					Packets:   2000,   // avg 75 bytes/packet
				},
			},
			wantAlerts: 0,
		},
		{
			name: "large packets but low volume (not tunneling)",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("192.168.1.202"),
					DstAddr:   net.ParseIP("8.8.8.8"),
					Protocol:  1,
					Bytes:     1000, // < 100KB
					Packets:   2,    // avg 500 bytes/packet
				},
			},
			wantAlerts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewRingBuffer(100)
			_ = store.Insert(tt.flows)

			detector := ICMPTunnelingDetector{}
			cfg := config.AnalysisConfig{
				QueryWindow: 5 * time.Minute,
			}

			advisories := detector.Analyze(store, cfg)
			if len(advisories) != tt.wantAlerts {
				t.Errorf("Analyze() returned %d advisories, want %d", len(advisories), tt.wantAlerts)
			}

			if tt.wantAlerts > 0 && len(advisories) > 0 {
				if advisories[0].Title != tt.wantTitle {
					t.Errorf("Analyze() title = %q, want %q", advisories[0].Title, tt.wantTitle)
				}
			}
		})
	}
}

func TestICMPTunnelingDetector_Error(t *testing.T) {
	store := &mockErrorStorage{}
	detector := ICMPTunnelingDetector{}
	cfg := config.AnalysisConfig{QueryWindow: 5 * time.Minute}

	advisories := detector.Analyze(store, cfg)
	if advisories != nil {
		t.Errorf("Expected nil advisories on storage error, got %v", advisories)
	}
}

func TestICMPTunnelingDetector_EmptyFlows(t *testing.T) {
	store := storage.NewRingBuffer(10)
	detector := ICMPTunnelingDetector{}
	cfg := config.AnalysisConfig{QueryWindow: 5 * time.Minute}

	advisories := detector.Analyze(store, cfg)
	if advisories != nil {
		t.Errorf("Expected nil advisories for empty flows, got %v", advisories)
	}
}
