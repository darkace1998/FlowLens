package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"github.com/darkace1998/FlowLens/internal/util"
)

// CryptominingDetector analyzes flow data to identify potential cryptocurrency
// mining activity by detecting persistent connections to common mining pool ports.
type CryptominingDetector struct{}

func (CryptominingDetector) Name() string { return "Cryptomining Detector" }

// miningPorts maps common mining pool destination ports to the protocol/currency.
var miningPorts = map[uint16]string{
	3333:  "Stratum (Monero/Bitcoin)",
	4444:  "Stratum (Monero/Bitcoin)",
	5555:  "Stratum (Monero/Bitcoin)",
	6666:  "Stratum (Monero/Bitcoin)",
	7777:  "Stratum (Monero/Bitcoin)",
	8332:  "Bitcoin RPC",
	8333:  "Bitcoin P2P",
	9332:  "Litecoin RPC",
	9333:  "Litecoin P2P",
	14444: "Stratum (Monero)",
}

const minMiningDurationSeconds = 60
const minMiningPackets = 100

// Analyze returns advisories about potential cryptocurrency mining activity.
func (CryptominingDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("CryptominingDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type connKey struct {
		srcIP   [16]byte
		dstIP   string
		dstPort uint16
	}

	type connStats struct {
		bytes        uint64
		packets      uint64
		totalDurSecs float64
	}

	conns := make(map[connKey]*connStats)

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
		// Mining is predominantly TCP.
		if f.Protocol != 6 {
			continue
		}

		if _, ok := miningPorts[f.DstPort]; !ok {
			continue
		}

		key := connKey{
			srcIP:   to16(f.SrcAddr),
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}

		s, ok := conns[key]
		if !ok {
			s = &connStats{}
			conns[key] = s
		}
		s.bytes += f.Bytes
		s.packets += f.Packets
		s.totalDurSecs += f.Duration.Seconds()
	}

	type result struct {
		key   connKey
		stats *connStats
	}
	var results []result

	for key, stats := range conns {
		if stats.totalDurSecs >= minMiningDurationSeconds && stats.packets >= minMiningPackets {
			results = append(results, result{key: key, stats: stats})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.totalDurSecs > results[j].stats.totalDurSecs
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))
	windowStr := formatWindowShort(queryWindow(cfg))

	for _, r := range results {
		srcStr := model.SafeIPString(r.key.srcIP[:])
		protoDesc := miningPorts[r.key.dstPort]

		sev := WARNING
		if r.stats.totalDurSecs >= minMiningDurationSeconds*5 || r.stats.bytes > 10*1024*1024 { // 10MB
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Cryptomining Activity: %s", srcStr),
			Description: fmt.Sprintf(
				"%s established a persistent connection to mining pool %s on port %d (%s) "+
					"exchanging %s (%s packets) over %.0f seconds in the last %s. "+
					"This indicates potential unauthorized cryptocurrency mining or malware infection.",
				srcStr, r.key.dstIP, r.key.dstPort, protoDesc, util.FormatBytes(r.stats.bytes),
				util.FormatCount(r.stats.packets), r.stats.totalDurSecs, windowStr,
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized mining software (e.g., XMRig). Consider blocking outbound traffic to %s.",
				srcStr, r.key.dstIP,
			),
		})
	}

	return advisories
}
