package analysis

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// BeaconingDetector analyzes flow data to identify periodic connection attempts,
// which is a classic indicator of malware Command & Control (C2) beaconing or
// automated telemetry.
type BeaconingDetector struct{}

func (BeaconingDetector) Name() string { return "Beaconing Detector" }

// Analyze returns advisories about periodic beaconing activity.
func (BeaconingDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("BeaconingDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type flowKey struct {
		srcIP   [16]byte
		dstIP   string
		dstPort uint16
		proto   uint8
	}

	// Group flows by source, destination, port, and protocol.
	groups := make(map[flowKey][]time.Time)

	to16 := func(ip []byte) [16]byte {
		var k [16]byte
		if len(ip) == 16 {
			copy(k[:], ip)
		} else if len(ip) == 4 {
			k[10] = 0xff
			k[11] = 0xff
			copy(k[12:], ip)
		}
		return k
	}

	for _, f := range flows {
		// Ignore ICMP, typically focus on TCP/UDP for beaconing
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		// Ignore very short flows if they are local, but we'll let everything through and filter by interval consistency.
		key := flowKey{
			srcIP:   to16(f.SrcAddr),
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
			proto:   f.Protocol,
		}
		groups[key] = append(groups[key], f.Timestamp)
	}

	type result struct {
		key         flowKey
		mean        float64
		stddev      float64
		cv          float64
		beaconCount int
		interval    time.Duration
	}

	var results []result

	for key, timestamps := range groups {
		if len(timestamps) < 10 { // Require at least 10 connections to establish periodicity
			continue
		}

		sort.Slice(timestamps, func(i, j int) bool {
			return timestamps[i].Before(timestamps[j])
		})

		// Group into bursts. If flows are within 5 seconds of each other, consider them part of the same burst.
		var bursts []time.Time
		currentBurstStart := timestamps[0]
		bursts = append(bursts, currentBurstStart)

		for i := 1; i < len(timestamps); i++ {
			if timestamps[i].Sub(currentBurstStart) > 5*time.Second {
				currentBurstStart = timestamps[i]
				bursts = append(bursts, currentBurstStart)
			}
		}

		if len(bursts) < 10 {
			continue
		}

		// Calculate intervals between bursts
		var intervals []float64
		var sum float64
		for i := 1; i < len(bursts); i++ {
			diff := bursts[i].Sub(bursts[i-1]).Seconds()
			intervals = append(intervals, diff)
			sum += diff
		}

		mean := sum / float64(len(intervals))

		// If the mean interval is too short (< 10s), it might just be a busy active connection (like a game or stream)
		// rather than a beacon. Real beacons are usually >= 10s.
		if mean < 10.0 {
			continue
		}

		var varianceSum float64
		for _, interval := range intervals {
			diff := interval - mean
			varianceSum += diff * diff
		}

		stddev := math.Sqrt(varianceSum / float64(len(intervals)))

		// Coefficient of Variation (CV) = stddev / mean
		cv := stddev / mean

		// Highly periodic traffic has a very low CV.
		if cv < 0.1 {
			results = append(results, result{
				key:         key,
				mean:        mean,
				stddev:      stddev,
				cv:          cv,
				beaconCount: len(bursts),
				interval:    time.Duration(mean * float64(time.Second)),
			})
		}
	}

	// Sort results by CV (lowest variance first), then by count (most beacons first)
	sort.Slice(results, func(i, j int) bool {
		if math.Abs(results[i].cv-results[j].cv) < 0.01 {
			return results[i].beaconCount > results[j].beaconCount
		}
		return results[i].cv < results[j].cv
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		srcStr := model.SafeIPString(r.key.srcIP[:])
		protoStr := model.ProtocolName(r.key.proto)

		sev := WARNING
		if r.beaconCount >= 50 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Beaconing Activity: %s → %s", srcStr, r.key.dstIP),
			Description: fmt.Sprintf(
				"%s established %d periodic %s connections to %s on port %d. "+
					"The average interval is %s (CV: %.3f). This highly regular pattern is typical of malware C2 beaconing or automated telemetry.",
				srcStr, r.beaconCount, protoStr, r.key.dstIP, r.key.dstPort, r.interval.Round(time.Second).String(), r.cv,
			),
			Action: fmt.Sprintf(
				"Investigate the process on %s communicating with %s. If unauthorized, block the destination IP.",
				srcStr, r.key.dstIP,
			),
		})
	}

	return advisories
}
