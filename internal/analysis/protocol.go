package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// ProtocolDistribution analyzes flow data to identify the distribution of
// network protocols and generates advisories for unusual patterns.
type ProtocolDistribution struct{}

func (ProtocolDistribution) Name() string { return "Protocol Distribution" }

// protoEntry is an internal type for protocol aggregation.
type protoEntry struct {
	Proto   uint8
	Name    string
	Bytes   uint64
	Packets uint64
}

// Analyze returns advisories about protocol distribution anomalies.
func (ProtocolDistribution) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, _ := store.Recent(10*time.Minute, 0)
	if len(flows) == 0 {
		return nil
	}

	report := buildProtocolReport(flows)
	var totalBytes uint64
	for _, e := range report {
		totalBytes += e.Bytes
	}

	if totalBytes == 0 {
		return nil
	}

	now := time.Now()
	var advisories []Advisory

	for _, e := range report {
		pct := float64(e.Bytes) / float64(totalBytes) * 100

		// Only flag protocols when something is wrong — normal operation = no advisory.
		var sev Severity
		var shouldReport bool

		switch {
		// Non-standard protocols consuming significant bandwidth.
		case e.Proto != 6 && e.Proto != 17 && e.Proto != 1 && pct > 5:
			sev = WARNING
			shouldReport = true
		// ICMP consuming >10% of traffic — possible flood.
		case e.Proto == 1 && pct > 10:
			sev = WARNING
			shouldReport = true
		}

		if shouldReport {
			advisories = append(advisories, Advisory{
				Severity:  sev,
				Timestamp: now,
				Title:     fmt.Sprintf("Protocol: %s (%.1f%%)", e.Name, pct),
				Description: fmt.Sprintf(
					"%s accounts for %.1f%% of traffic (%s bytes, %s packets).",
					e.Name, pct, formatBytesShort(e.Bytes), formatCountShort(e.Packets),
				),
				Action: actionForProtocol(sev, e.Name, pct),
			})
		}
	}

	return advisories
}

func actionForProtocol(sev Severity, name string, pct float64) string {
	switch sev {
	case WARNING:
		return fmt.Sprintf("Investigate %s traffic (%.1f%%) — may indicate abuse or misconfiguration.", name, pct)
	default:
		return "No action required — informational."
	}
}

func buildProtocolReport(flows []model.Flow) []protoEntry {
	m := make(map[uint8]*protoEntry)
	for _, f := range flows {
		if e, ok := m[f.Protocol]; ok {
			e.Bytes += f.Bytes
			e.Packets += f.Packets
		} else {
			m[f.Protocol] = &protoEntry{
				Proto:   f.Protocol,
				Name:    model.ProtocolName(f.Protocol),
				Bytes:   f.Bytes,
				Packets: f.Packets,
			}
		}
	}

	entries := make([]protoEntry, 0, len(m))
	for _, e := range m {
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Bytes > entries[j].Bytes
	})
	return entries
}
