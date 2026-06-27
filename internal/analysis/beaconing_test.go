package analysis

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestBeaconingDetector_Analyze(t *testing.T) {
	cfg := config.AnalysisConfig{QueryWindow: time.Hour}
	now := time.Now()

	detector := BeaconingDetector{}

	t.Run("No flows", func(t *testing.T) {
		store := storage.NewRingBuffer(100)
		advisories := detector.Analyze(store, cfg)
		if len(advisories) != 0 {
			t.Errorf("expected 0 advisories, got %d", len(advisories))
		}
	})

	t.Run("Highly periodic beaconing", func(t *testing.T) {
		flows := make([]model.Flow, 0, 20)
		for i := 0; i < 20; i++ {
			flows = append(flows, model.Flow{
				Timestamp: now.Add(time.Duration(i*30) * time.Second),
				SrcAddr:   net.ParseIP("192.168.1.100"),
				DstAddr:   net.ParseIP("10.0.0.1"),
				SrcPort:   uint16(10000 + i),
				DstPort:   443,
				Protocol:  6,
			})
		}

		store := storage.NewRingBuffer(1000)
		store.Insert(flows)
		advisories := detector.Analyze(store, cfg)

		if len(advisories) != 1 {
			t.Fatalf("expected 1 advisory, got %d", len(advisories))
		}

		adv := advisories[0]
		if adv.Severity != WARNING {
			t.Errorf("expected severity %s, got %s", WARNING, adv.Severity)
		}
	})

	t.Run("Random/Jittery non-beaconing traffic", func(t *testing.T) {
		intervals := []int{10, 50, 10, 80, 20, 60, 5, 45, 90, 15, 75, 20, 100, 30}
		flows := make([]model.Flow, 0, len(intervals))
		current := now
		for i, interval := range intervals {
			current = current.Add(time.Duration(interval) * time.Second)
			flows = append(flows, model.Flow{
				Timestamp: current,
				SrcAddr:   net.ParseIP("192.168.1.101"),
				DstAddr:   net.ParseIP("10.0.0.2"),
				SrcPort:   uint16(20000 + i),
				DstPort:   80,
				Protocol:  6,
			})
		}

		store := storage.NewRingBuffer(1000)
		store.Insert(flows)
		advisories := detector.Analyze(store, cfg)

		if len(advisories) != 0 {
			t.Fatalf("expected 0 advisories for high variance, got %d", len(advisories))
		}
	})

	t.Run("Burst handling", func(t *testing.T) {
		flows := make([]model.Flow, 0, 45)
		current := now
		for i := 0; i < 15; i++ {
			for j := 0; j < 3; j++ {
				flows = append(flows, model.Flow{
					Timestamp: current.Add(time.Duration(j) * time.Millisecond * 100),
					SrcAddr:   net.ParseIP("192.168.1.102"),
					DstAddr:   net.ParseIP("10.0.0.3"),
					SrcPort:   uint16(30000 + i*3 + j),
					DstPort:   443,
					Protocol:  6,
				})
			}
			current = current.Add(60 * time.Second)
		}

		store := storage.NewRingBuffer(1000)
		store.Insert(flows)
		advisories := detector.Analyze(store, cfg)

		if len(advisories) != 1 {
			t.Fatalf("expected 1 advisory due to successful burst grouping, got %d", len(advisories))
		}
	})

	t.Run("Short interval traffic (not beaconing)", func(t *testing.T) {
		flows := make([]model.Flow, 0, 50)
		for i := 0; i < 50; i++ {
			flows = append(flows, model.Flow{
				Timestamp: now.Add(time.Duration(i*2) * time.Second),
				SrcAddr:   net.ParseIP("192.168.1.103"),
				DstAddr:   net.ParseIP("10.0.0.4"),
				SrcPort:   uint16(40000 + i),
				DstPort:   12345,
				Protocol:  17,
			})
		}

		store := storage.NewRingBuffer(1000)
		store.Insert(flows)
		advisories := detector.Analyze(store, cfg)

		if len(advisories) != 0 {
			t.Fatalf("expected 0 advisories for short intervals (<10s), got %d", len(advisories))
		}
	})
}
