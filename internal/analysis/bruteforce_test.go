package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestBruteForceDetector(t *testing.T) {
	cfg := config.AnalysisConfig{QueryWindow: 10 * time.Minute}

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
			name: "Normal login traffic (below threshold)",
			setupFlows: func() []model.Flow {
				flows := make([]model.Flow, 0, 10)
				for i := 0; i < 10; i++ {
					// 10 attempts to SSH (port 22)
					flows = append(flows, makeFlow("1.2.3.4", "10.0.0.1", uint16(10000+i), 22, 6, 100, 1))
				}
				return flows
			},
			expectedAlert: 0,
		},
		{
			name: "Non-login ports (above threshold)",
			setupFlows: func() []model.Flow {
				flows := make([]model.Flow, 0, 150)
				for i := 0; i < 150; i++ {
					// 150 connections to HTTP (port 80)
					flows = append(flows, makeFlow("1.2.3.4", "10.0.0.1", uint16(10000+i), 80, 6, 100, 1))
				}
				return flows
			},
			expectedAlert: 0,
		},
		{
			name: "UDP traffic on login port (ignored)",
			setupFlows: func() []model.Flow {
				flows := make([]model.Flow, 0, 150)
				for i := 0; i < 150; i++ {
					// 150 UDP flows to port 22
					flows = append(flows, makeFlow("1.2.3.4", "10.0.0.1", uint16(10000+i), 22, 17, 100, 1))
				}
				return flows
			},
			expectedAlert: 0,
		},
		{
			name: "Brute force attack (warning threshold)",
			setupFlows: func() []model.Flow {
				flows := make([]model.Flow, 0, 150)
				for i := 0; i < 150; i++ {
					// 150 TCP flows to SSH (port 22) from same source IP, different source ports
					flows = append(flows, makeFlow("1.2.3.4", "10.0.0.1", uint16(10000+i), 22, 6, 100, 1))
				}
				return flows
			},
			expectedAlert: 1,
			expectedSev:   WARNING,
			checkTitle:    "Brute Force Attack: 1.2.3.4 → 10.0.0.1 (SSH)",
		},
		{
			name: "Brute force attack (critical threshold)",
			setupFlows: func() []model.Flow {
				flows := make([]model.Flow, 0, 600)
				for i := 0; i < 600; i++ {
					// 600 TCP flows to RDP (port 3389) from same source IP, different source ports
					flows = append(flows, makeFlow("2.3.4.5", "10.0.0.2", uint16(10000+i), 3389, 6, 100, 1))
				}
				return flows
			},
			expectedAlert: 1,
			expectedSev:   CRITICAL,
			checkTitle:    "Brute Force Attack: 2.3.4.5 → 10.0.0.2 (RDP)",
		},
		{
			name: "Multiple targets brute forced",
			setupFlows: func() []model.Flow {
				flows := make([]model.Flow, 0, 300)
				for i := 0; i < 150; i++ {
					// Target 1: 10.0.0.1 on SSH
					flows = append(flows, makeFlow("1.2.3.4", "10.0.0.1", uint16(10000+i), 22, 6, 100, 1))
					// Target 2: 10.0.0.2 on FTP
					flows = append(flows, makeFlow("1.2.3.4", "10.0.0.2", uint16(10000+i), 21, 6, 100, 1))
				}
				return flows
			},
			expectedAlert: 2,
			expectedSev:   WARNING,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewRingBuffer(10000)
			if flows := tc.setupFlows(); flows != nil {
				_ = store.Insert(flows)
			}

			detector := BruteForceDetector{}
			advs := detector.Analyze(store, cfg)

			if len(advs) != tc.expectedAlert {
				t.Fatalf("expected %d advisories, got %d", tc.expectedAlert, len(advs))
			}

			if tc.expectedAlert > 0 {
				if advs[0].Severity != tc.expectedSev {
					t.Errorf("expected severity %s, got %s", tc.expectedSev, advs[0].Severity)
				}
				if tc.checkTitle != "" {
					found := false
					for _, a := range advs {
						if a.Title == tc.checkTitle {
							found = true
							break
						}
					}
					if !found {
						titles := make([]string, 0, len(advs))
						for _, a := range advs {
							titles = append(titles, a.Title)
						}
						t.Errorf("expected title %q not found in alerts: %v", tc.checkTitle, titles)
					}
				}

				// Verify description includes expected strings
				if tc.checkTitle != "" {
					// Grab the advisory we're checking
					var checkAdv Advisory
					for _, a := range advs {
						if a.Title == tc.checkTitle {
							checkAdv = a
							break
						}
					}
					if !strings.Contains(checkAdv.Description, "potential brute-force login attack") {
						t.Errorf("description missing key phrase. got: %s", checkAdv.Description)
					}
				}
			}
		})
	}
}

func TestBruteForceDetector_StorageError(t *testing.T) {
	detector := BruteForceDetector{}
	cfg := config.AnalysisConfig{}

	// Test storage error
	advs := detector.Analyze(mockErrorStorage{}, cfg)
	if advs != nil {
		t.Errorf("Expected nil advisories on storage error, got %d", len(advs))
	}
}
