package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestExposedServiceDetector(t *testing.T) {
	cfg := config.AnalysisConfig{QueryWindow: 10 * time.Minute}

	makeFlowWithIPs := func(src, dst string, dstPort uint16, packets uint64) model.Flow {
		return model.Flow{
			Timestamp: time.Now(),
			SrcAddr:   net.ParseIP(src),
			DstAddr:   net.ParseIP(dst),
			DstPort:   dstPort,
			Protocol:  6,
			Bytes:     1000,
			Packets:   packets,
		}
	}

	tests := []struct {
		name          string
		setupFlows    func() []model.Flow
		expectedAlert int
		expectedSev   Severity
		checkTitle    string
	}{
		{
			name: "No traffic",
			setupFlows: func() []model.Flow {
				return nil
			},
			expectedAlert: 0,
		},
		{
			name: "Public to Public (ignored)",
			setupFlows: func() []model.Flow {
				return []model.Flow{
					makeFlowWithIPs("8.8.8.8", "1.1.1.1", 3389, 5),
				}
			},
			expectedAlert: 0,
		},
		{
			name: "Private to Private (ignored)",
			setupFlows: func() []model.Flow {
				return []model.Flow{
					makeFlowWithIPs("192.168.1.10", "10.0.0.5", 3389, 5),
				}
			},
			expectedAlert: 0,
		},
		{
			name: "Background scanner noise (Packets < 3)",
			setupFlows: func() []model.Flow {
				return []model.Flow{
					// Public IP hitting internal RDP, but only 1 packet (e.g. single SYN)
					makeFlowWithIPs("203.0.113.5", "10.0.0.5", 3389, 1),
				}
			},
			expectedAlert: 0,
		},
		{
			name: "Non-sensitive port (ignored)",
			setupFlows: func() []model.Flow {
				return []model.Flow{
					// Public IP to internal HTTP
					makeFlowWithIPs("203.0.113.5", "10.0.0.5", 80, 10),
				}
			},
			expectedAlert: 0,
		},
		{
			name: "Inbound exposed service (Critical)",
			setupFlows: func() []model.Flow {
				return []model.Flow{
					// Public IP to internal RDP, 5 packets
					makeFlowWithIPs("203.0.113.5", "10.0.0.5", 3389, 5),
				}
			},
			expectedAlert: 1,
			expectedSev:   CRITICAL,
			checkTitle:    "Exposed Sensitive Service: 10.0.0.5:3389 (RDP)",
		},
		{
			name: "Outbound sensitive traffic (Warning)",
			setupFlows: func() []model.Flow {
				return []model.Flow{
					// Internal IP to public MySQL, 10 packets
					makeFlowWithIPs("192.168.1.10", "203.0.113.5", 3306, 10),
				}
			},
			expectedAlert: 1,
			expectedSev:   WARNING,
			checkTitle:    "Outbound Sensitive Traffic: 192.168.1.10 → 203.0.113.5:3306 (MySQL)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewRingBuffer(100)
			if flows := tc.setupFlows(); flows != nil {
				_ = store.Insert(flows)
			}

			detector := ExposedServiceDetector{}
			advs := detector.Analyze(store, cfg)

			if len(advs) != tc.expectedAlert {
				t.Fatalf("expected %d advisories, got %d", tc.expectedAlert, len(advs))
			}

			if tc.expectedAlert > 0 {
				if advs[0].Severity != tc.expectedSev {
					t.Errorf("expected severity %s, got %s", tc.expectedSev, advs[0].Severity)
				}
				if tc.checkTitle != "" && advs[0].Title != tc.checkTitle {
					t.Errorf("expected title %q, got %q", tc.checkTitle, advs[0].Title)
				}
			}
		})
	}
}

func TestExposedServiceDetector_StorageError(t *testing.T) {
	detector := ExposedServiceDetector{}
	cfg := config.AnalysisConfig{}

	advs := detector.Analyze(mockErrorStorage{}, cfg)
	if advs != nil {
		t.Errorf("Expected nil advisories on storage error, got %d", len(advs))
	}
}
