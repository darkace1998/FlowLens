package analysis

import (
	"fmt"
	"math"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// AnomalyDetector compares recent traffic volume against a baseline window
// to detect significant spikes or drops in bytes and packets.
type AnomalyDetector struct{}

func (AnomalyDetector) Name() string { return "Anomaly Detection" }

// Analyze compares the most recent analysis interval's traffic against
// the average and standard deviation computed over the baseline window.
// It generates advisories when current traffic deviates significantly.
func (AnomalyDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	// Use the analysis interval as the "current" sample window.
	sampleWindow := cfg.Interval
	if sampleWindow <= 0 {
		sampleWindow = 60 * time.Second
	}

	baselineWindow := cfg.AnomalyBaselineWindow
	if baselineWindow <= 0 {
		baselineWindow = 7 * 24 * time.Hour
	}

	// We need at least 2 sample windows in the baseline to compute meaningful stats.
	// Since the ring buffer only holds ~10 min of data, use what we have.
	window := queryWindow(cfg)
	allFlows, err := store.Recent(window, 0)
	if err != nil {
		logging.Default().Error("AnomalyDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(allFlows) == 0 {
		return nil
	}

	now := time.Now()
	currentCutoff := now.Add(-sampleWindow)
	// Use the remaining flows as the baseline.
	baselineCutoff := now.Add(-window)

	var currentBytes, currentPkts uint64
	var currentCount int

	type bucket struct {
		bytes   uint64
		packets uint64
	}

	// Divide all flows into the current window and baseline buckets.
	// Each bucket is one sample-window wide.
	bucketCount := int(window/sampleWindow) - 1
	if bucketCount < 1 {
		bucketCount = 1
	}
	buckets := make([]bucket, bucketCount)

	for _, f := range allFlows {
		if !f.Timestamp.Before(currentCutoff) {
			// Current window.
			currentBytes += f.Bytes
			currentPkts += f.Packets
			currentCount++
		} else if !f.Timestamp.Before(baselineCutoff) {
			// Baseline: assign to appropriate bucket.
			age := now.Sub(f.Timestamp) - sampleWindow
			idx := int(age / sampleWindow)
			if idx >= bucketCount {
				idx = bucketCount - 1
			}
			if idx < 0 {
				idx = 0
			}
			buckets[idx].bytes += f.Bytes
			buckets[idx].packets += f.Packets
		}
	}

	// Need baseline data to compare against.
	nonEmptyBuckets := 0
	var sumBytes float64
	for _, b := range buckets {
		if b.bytes > 0 || b.packets > 0 {
			nonEmptyBuckets++
			sumBytes += float64(b.bytes)
		}
	}

	if nonEmptyBuckets < 2 {
		return nil
	}

	meanBytes := sumBytes / float64(nonEmptyBuckets)

	// Compute standard deviation.
	var varianceBytes float64
	for _, b := range buckets {
		if b.bytes > 0 || b.packets > 0 {
			diffB := float64(b.bytes) - meanBytes
			varianceBytes += diffB * diffB
		}
	}
	stddevBytes := math.Sqrt(varianceBytes / float64(nonEmptyBuckets))

	var advisories []Advisory

	// Check for spike: current > mean + 2*stddev.
	if currentCount > 0 && meanBytes > 0 {
		curB := float64(currentBytes)
		spikeThreshold := meanBytes + 2*stddevBytes
		dropThreshold := meanBytes / 4

		if curB > spikeThreshold && stddevBytes > 0 {
			deviations := (curB - meanBytes) / stddevBytes
			sev := WARNING
			if deviations > 4 {
				sev = CRITICAL
			}

			advisories = append(advisories, Advisory{
				Severity:  sev,
				Timestamp: now,
				Title:     "Traffic Spike Detected",
				Description: fmt.Sprintf(
					"Current interval: %s bytes (%.1fσ above baseline mean of %s). "+
						"Baseline stddev: %s over %d samples.",
					formatBytesShort(currentBytes),
					deviations,
					formatBytesShort(uint64(meanBytes)),
					formatBytesShort(uint64(stddevBytes)),
					nonEmptyBuckets,
				),
				Action: spikeAction(sev),
			})
		}

		// Check for drop: current < mean/4 (75%+ drop from baseline).
		if curB < dropThreshold && meanBytes > 1000 {
			pctDrop := (1 - curB/meanBytes) * 100
			sev := WARNING
			if pctDrop > 90 {
				sev = CRITICAL
			}

			advisories = append(advisories, Advisory{
				Severity:  sev,
				Timestamp: now,
				Title:     "Traffic Drop Detected",
				Description: fmt.Sprintf(
					"Current interval: %s bytes (%.0f%% below baseline mean of %s). "+
						"Possible link failure or upstream issue.",
					formatBytesShort(currentBytes),
					pctDrop,
					formatBytesShort(uint64(meanBytes)),
				),
				Action: dropAction(sev),
			})
		}
	}

	return advisories
}

func spikeAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — extreme traffic deviation detected. Check for DDoS or runaway process."
	default:
		return "Monitor closely — traffic is significantly above baseline. May indicate burst or attack."
	}
}

func dropAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Check network connectivity immediately — traffic nearly absent vs. baseline."
	default:
		return "Verify upstream links and collector connectivity — traffic well below expected levels."
	}
}
