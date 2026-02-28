package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// TopTalkers analyzes flow data to identify the highest-volume sources and
// destinations by byte count and generates advisories for dominant hosts.
type TopTalkers struct{}

func (TopTalkers) Name() string { return "Top Talkers" }

// talkerEntry is an internal type for aggregation.
type talkerEntry struct {
	IP      string
	Bytes   uint64
	Packets uint64
}

// Analyze returns advisories about hosts consuming disproportionate bandwidth.
func (TopTalkers) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("TopTalkers: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	srcMap := make(map[string]*talkerEntry)
	var totalBytes uint64

	for _, f := range flows {
		totalBytes += f.Bytes
		src := model.SafeIPString(f.SrcAddr)
		if e, ok := srcMap[src]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			srcMap[src] = &talkerEntry{IP: src, Bytes: f.Bytes, Packets: f.Packets}
		}
	}

	if totalBytes == 0 {
		return nil
	}

	// Sort by bytes descending.
	entries := make([]talkerEntry, 0, len(srcMap))
	for _, e := range srcMap {
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Bytes > entries[j].Bytes
	})

	n := cfg.TopTalkersCount
	if n > len(entries) {
		n = len(entries)
	}

	now := time.Now()
	var advisories []Advisory

	for _, e := range entries[:n] {
		pct := float64(e.Bytes) / float64(totalBytes) * 100

		// Only generate advisories when a host exceeds a meaningful threshold.
		// A host at 20% of bandwidth is normal — silence is a feature.
		if pct <= 25 {
			continue
		}

		sev := WARNING
		if pct > 50 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Top Talker: %s", e.IP),
			Description: fmt.Sprintf(
				"%s is responsible for %.1f%% of traffic (%s, %s packets) in the last 10 minutes.",
				e.IP, pct, formatBytesShort(e.Bytes), formatCountShort(e.Packets),
			),
			Action: actionForTalker(sev, e.IP),
		})
	}

	return advisories
}

func actionForTalker(sev Severity, ip string) string {
	switch sev {
	case CRITICAL:
		return fmt.Sprintf("Investigate %s immediately — consuming majority of bandwidth.", ip)
	default:
		return fmt.Sprintf("Monitor %s — significant bandwidth usage detected.", ip)
	}
}

func formatBytesShort(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatCountShort(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1000000)
}

// BuildTopTalkersReport generates a top-talkers summary from flows.
// Exported for use by other packages (e.g., dashboard).
func BuildTopTalkersReport(flows []model.Flow, n int) []talkerEntry {
	srcMap := make(map[string]*talkerEntry)
	for _, f := range flows {
		src := model.SafeIPString(f.SrcAddr)
		if e, ok := srcMap[src]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			srcMap[src] = &talkerEntry{IP: src, Bytes: f.Bytes, Packets: f.Packets}
		}
	}

	entries := make([]talkerEntry, 0, len(srcMap))
	for _, e := range srcMap {
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Bytes > entries[j].Bytes
	})

	if n > len(entries) {
		n = len(entries)
	}
	return entries[:n]
}
