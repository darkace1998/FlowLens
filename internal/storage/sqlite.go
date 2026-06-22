package storage

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"

	_ "modernc.org/sqlite"
)

// isColumnExistsError returns true if the error indicates a duplicate column.
func isColumnExistsError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column")
}

// SQLiteStore persists flow records in a SQLite database with WAL mode.
//
// Scalability note: SQLite is well-suited for single-node deployments with
// up to ~5–10 million flow records. Beyond that scale, write contention and
// query latency may increase significantly. For higher throughput or
// multi-node deployments, consider migrating to a purpose-built time-series
// database (e.g. InfluxDB, TimescaleDB, or ClickHouse) while keeping the
// FlowService/ReportService interfaces unchanged in the web layer.
type SQLiteStore struct {
	db            *sql.DB
	retention     time.Duration
	pruneInterval time.Duration
	stopPrune     chan struct{}
	pruneWg       sync.WaitGroup
}

// NewSQLiteStore opens (or creates) a SQLite database at the given path,
// enables WAL mode, creates the flows table, and starts a background
// pruning goroutine based on the configured retention and prune interval.
func NewSQLiteStore(path string, retention, pruneInterval time.Duration) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// Enable WAL mode for concurrent reads during writes.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close() // nolint:errcheck // error ignored in cleanup path
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	// Create the flows table if it doesn't exist.
	createSQL := `CREATE TABLE IF NOT EXISTS flows (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp   DATETIME NOT NULL,
		src_addr    TEXT NOT NULL,
		dst_addr    TEXT NOT NULL,
		src_port    INTEGER NOT NULL,
		dst_port    INTEGER NOT NULL,
		protocol    INTEGER NOT NULL,
		bytes       INTEGER NOT NULL,
		packets     INTEGER NOT NULL,
		tcp_flags   INTEGER NOT NULL,
		tos         INTEGER NOT NULL,
		input_iface  INTEGER NOT NULL,
		output_iface INTEGER NOT NULL,
		src_as      INTEGER NOT NULL,
		dst_as      INTEGER NOT NULL,
		duration_ns INTEGER NOT NULL,
		exporter_ip TEXT NOT NULL,
		app_proto   TEXT NOT NULL DEFAULT '',
		app_category TEXT NOT NULL DEFAULT '',
		rtt_us      INTEGER NOT NULL DEFAULT 0,
		throughput_bps REAL NOT NULL DEFAULT 0,
		retransmissions INTEGER NOT NULL DEFAULT 0,
		out_of_order    INTEGER NOT NULL DEFAULT 0,
		packet_loss     INTEGER NOT NULL DEFAULT 0,
		jitter_us       INTEGER NOT NULL DEFAULT 0,
		mos             REAL NOT NULL DEFAULT 0,
		src_mac         TEXT NOT NULL DEFAULT '',
		dst_mac         TEXT NOT NULL DEFAULT '',
		vlan_id         INTEGER NOT NULL DEFAULT 0,
		ether_type      INTEGER NOT NULL DEFAULT 0,
		nat_src_addr TEXT NOT NULL DEFAULT '',
		nat_dst_addr TEXT NOT NULL DEFAULT '',
		nat_src_port INTEGER NOT NULL DEFAULT 0,
		nat_dst_port INTEGER NOT NULL DEFAULT 0,
		nat_events   INTEGER NOT NULL DEFAULT 0,
		ipv6_flow_label INTEGER NOT NULL DEFAULT 0,
		src_mask INTEGER NOT NULL DEFAULT 0,
		dst_mask INTEGER NOT NULL DEFAULT 0,
		is_multicast INTEGER NOT NULL DEFAULT 0,
		icmp_type INTEGER NOT NULL DEFAULT 0,
		icmp_code INTEGER NOT NULL DEFAULT 0,
		ip_total_length INTEGER NOT NULL DEFAULT 0,
		ip_header_length INTEGER NOT NULL DEFAULT 0,
		ttl INTEGER NOT NULL DEFAULT 0,
		udp_length INTEGER NOT NULL DEFAULT 0,
		igmp_type INTEGER NOT NULL DEFAULT 0,
		gateway TEXT NOT NULL DEFAULT '',
		sys_init_time DATETIME NOT NULL DEFAULT '1970-01-01T00:00:00Z',
		tcp_ack_num INTEGER NOT NULL DEFAULT 0,
		tcp_window_size INTEGER NOT NULL DEFAULT 0
	)`
	if _, err := db.Exec(createSQL); err != nil {
		_ = db.Close() // nolint:errcheck // error ignored in cleanup path
		return nil, fmt.Errorf("creating flows table: %w", err)
	}

	// Migrate existing databases: add app_proto and app_category columns if missing.
	// Errors are expected if columns already exist; only log unexpected failures.
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN app_proto TEXT NOT NULL DEFAULT ''"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration app_proto: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN app_category TEXT NOT NULL DEFAULT ''"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration app_category: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN rtt_us INTEGER NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration rtt_us: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN throughput_bps REAL NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration throughput_bps: %v", err)
		}
	}
	for _, col := range []string{"retransmissions", "out_of_order", "packet_loss"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN jitter_us INTEGER NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration jitter_us: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN mos REAL NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration mos: %v", err)
		}
	}
	for _, col := range []string{"src_mac", "dst_mac"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " TEXT NOT NULL DEFAULT ''"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	for _, col := range []string{"vlan_id", "ether_type"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	// NAT fields migration
	for _, col := range []string{"nat_src_addr", "nat_dst_addr"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " TEXT NOT NULL DEFAULT ''"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	for _, col := range []string{"nat_src_port", "nat_dst_port", "nat_events"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	// IPv6 fields migration
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN ipv6_flow_label INTEGER NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration ipv6_flow_label: %v", err)
		}
	}
	// Network addressing fields migration
	for _, col := range []string{"src_mask", "dst_mask", "is_multicast"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	// ICMP fields migration
	for _, col := range []string{"icmp_type", "icmp_code"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	// IP header fields migration
	for _, col := range []string{"ip_total_length", "ip_header_length", "ttl"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}
	// UDP fields migration
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN udp_length INTEGER NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration udp_length: %v", err)
		}
	}
	// IGMP fields migration
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN igmp_type INTEGER NOT NULL DEFAULT 0"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration igmp_type: %v", err)
		}
	}
	// Routing fields migration
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN gateway TEXT NOT NULL DEFAULT ''"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration gateway: %v", err)
		}
	}
	// Timing fields migration
	if _, err := db.Exec("ALTER TABLE flows ADD COLUMN sys_init_time DATETIME NOT NULL DEFAULT '1970-01-01T00:00:00Z'"); err != nil {
		if !isColumnExistsError(err) {
			logging.Default().Warn("Migration sys_init_time: %v", err)
		}
	}
	// TCP details migration
	for _, col := range []string{"tcp_ack_num", "tcp_window_size"} {
		if _, err := db.Exec("ALTER TABLE flows ADD COLUMN " + col + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			if !isColumnExistsError(err) {
				logging.Default().Warn("Migration %s: %v", col, err)
			}
		}
	}

	// Create index on timestamp for efficient time-range queries and pruning.
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp)"); err != nil {
		_ = db.Close() // nolint:errcheck // error ignored in cleanup path
		return nil, fmt.Errorf("creating timestamp index: %w", err)
	}

	// SQLite uses file-level locking; limit to one open connection to avoid
	// SQLITE_BUSY errors from concurrent writers.
	db.SetMaxOpenConns(1)

	s := &SQLiteStore{
		db:            db,
		retention:     retention,
		pruneInterval: pruneInterval,
		stopPrune:     make(chan struct{}),
	}

	// Start background pruning.
	s.pruneWg.Add(1)
	go s.pruneLoop()

	return s, nil
}

// Insert stores one or more flow records in the database.
func (s *SQLiteStore) Insert(flows []model.Flow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.Prepare(`INSERT INTO flows
		(timestamp, src_addr, dst_addr, src_port, dst_port, protocol, bytes, packets, tcp_flags, tos, input_iface, output_iface, src_as, dst_as, duration_ns, exporter_ip, app_proto, app_category, rtt_us, throughput_bps, retransmissions, out_of_order, packet_loss, jitter_us, mos, src_mac, dst_mac, vlan_id, ether_type, nat_src_addr, nat_dst_addr, nat_src_port, nat_dst_port, nat_events, ipv6_flow_label, src_mask, dst_mask, is_multicast, icmp_type, icmp_code, ip_total_length, ip_header_length, ttl, udp_length, igmp_type, gateway, sys_init_time, tcp_ack_num, tcp_window_size)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close() // nolint:errcheck // error ignored, statement will be closed when context is done

	// Reusing an argument slice over dynamic bulk inserts is faster for modernc.org/sqlite
	// and minimizes garbage collection overhead in the loop.
	args := make([]interface{}, 49)
	for i := range flows {
		f := &flows[i]
		args[0] = f.Timestamp.UTC()
		args[1] = model.SafeIPString(f.SrcAddr)
		args[2] = model.SafeIPString(f.DstAddr)
		args[3] = f.SrcPort
		args[4] = f.DstPort
		args[5] = f.Protocol
		args[6] = f.Bytes
		args[7] = f.Packets
		args[8] = f.TCPFlags
		args[9] = f.ToS
		args[10] = f.InputIface
		args[11] = f.OutputIface
		args[12] = f.SrcAS
		args[13] = f.DstAS
		args[14] = f.Duration.Nanoseconds()
		args[15] = model.SafeIPString(f.ExporterIP)
		args[16] = f.AppProto
		args[17] = f.AppCat
		args[18] = f.RTTMicros
		args[19] = f.ThroughputBPS
		args[20] = f.Retransmissions
		args[21] = f.OutOfOrder
		args[22] = f.PacketLoss
		args[23] = f.JitterMicros
		args[24] = f.MOS
		args[25] = model.FormatMAC(f.SrcMAC)
		args[26] = model.FormatMAC(f.DstMAC)
		args[27] = f.VLAN
		args[28] = f.EtherType
		// NAT fields
		args[29] = model.SafeIPString(f.NatSrcAddr)
		args[30] = model.SafeIPString(f.NatDstAddr)
		args[31] = f.NatSrcPort
		args[32] = f.NatDstPort
		args[33] = f.NatEvents
		// IPv6 fields
		args[34] = f.IPv6FlowLabel
		// Network addressing fields
		args[35] = f.SrcMask
		args[36] = f.DstMask
		args[37] = f.IsMulticast
		// ICMP fields
		args[38] = f.ICMPType
		args[39] = f.ICMPCode
		// IP header fields
		args[40] = f.IPTotalLength
		args[41] = f.IPHeaderLength
		args[42] = f.TTL
		// UDP fields
		args[43] = f.UDPLength
		// IGMP fields
		args[44] = f.IGMPType
		// Routing fields
		args[45] = model.SafeIPString(f.Gateway)
		// Timing fields
		args[46] = f.SysInitTime.UTC()
		// TCP details
		args[47] = f.TCPAckNum
		args[48] = f.TCPWindowSize

		if _, err := stmt.Exec(args...); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert flow: %w", err)
		}
	}

	return tx.Commit()
}

// Recent returns flow records from the last duration d, most recent first.
// If limit > 0, at most limit records are returned.
func (s *SQLiteStore) Recent(d time.Duration, limit int) ([]model.Flow, error) {
	cutoff := time.Now().UTC().Add(-d)

	query := "SELECT timestamp, src_addr, dst_addr, src_port, dst_port, protocol, " +
		"bytes, packets, tcp_flags, tos, input_iface, output_iface, " +
		"src_as, dst_as, duration_ns, exporter_ip, app_proto, app_category, " +
		"rtt_us, throughput_bps, retransmissions, out_of_order, packet_loss, " +
		"jitter_us, mos, src_mac, dst_mac, vlan_id, ether_type, " +
		"nat_src_addr, nat_dst_addr, nat_src_port, nat_dst_port, nat_events, " +
		"ipv6_flow_label, src_mask, dst_mask, is_multicast, " +
		"icmp_type, icmp_code, ip_total_length, ip_header_length, ttl, " +
		"udp_length, igmp_type, gateway, sys_init_time, tcp_ack_num, tcp_window_size " +
		"FROM flows WHERE timestamp >= ? ORDER BY timestamp DESC"

	var rows *sql.Rows
	var err error
	if limit > 0 {
		query += " LIMIT ?"
		rows, err = s.db.Query(query, cutoff, limit)
	} else {
		rows, err = s.db.Query(query, cutoff)
	}
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	defer rows.Close() // nolint:errcheck // error ignored, rows will be closed when done

	var flows []model.Flow //nolint:prealloc // row count unknown until iteration
	for rows.Next() {
		var f model.Flow
		var ts time.Time
		var srcAddr, dstAddr, exporterIP string
		var srcMAC, dstMAC string
		var durationNs int64
		// NAT fields
		var natSrcAddr, natDstAddr, gateway string
		var isMulticastBit uint8

		err := rows.Scan(
			&ts,
			&srcAddr, &dstAddr,
			&f.SrcPort, &f.DstPort, &f.Protocol,
			&f.Bytes, &f.Packets, &f.TCPFlags, &f.ToS,
			&f.InputIface, &f.OutputIface,
			&f.SrcAS, &f.DstAS,
			&durationNs,
			&exporterIP,
			&f.AppProto, &f.AppCat,
			&f.RTTMicros, &f.ThroughputBPS,
			&f.Retransmissions, &f.OutOfOrder, &f.PacketLoss,
			&f.JitterMicros, &f.MOS,
			&srcMAC, &dstMAC,
			&f.VLAN, &f.EtherType,
			// NAT fields
			&natSrcAddr, &natDstAddr,
			&f.NatSrcPort, &f.NatDstPort, &f.NatEvents,
			// IPv6 fields
			&f.IPv6FlowLabel,
			// Network addressing fields
			&f.SrcMask, &f.DstMask, &isMulticastBit,
			// ICMP fields
			&f.ICMPType, &f.ICMPCode,
			// IP header fields
			&f.IPTotalLength, &f.IPHeaderLength, &f.TTL,
			// UDP fields
			&f.UDPLength,
			// IGMP fields
			&f.IGMPType,
			// Routing fields
			&gateway,
			// Timing fields
			&f.SysInitTime,
			// TCP details
			&f.TCPAckNum, &f.TCPWindowSize,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		f.Timestamp = ts
		f.SrcAddr = net.ParseIP(srcAddr)
		f.DstAddr = net.ParseIP(dstAddr)
		f.ExporterIP = net.ParseIP(exporterIP)
		f.Duration = time.Duration(durationNs)
		if srcMAC != "" && srcMAC != "—" {
			f.SrcMAC, _ = net.ParseMAC(srcMAC)
		}
		if dstMAC != "" && dstMAC != "—" {
			f.DstMAC, _ = net.ParseMAC(dstMAC)
		}
		// NAT fields
		f.NatSrcAddr = net.ParseIP(natSrcAddr)
		f.NatDstAddr = net.ParseIP(natDstAddr)
		// Network addressing fields
		f.IsMulticast = isMulticastBit != 0
		// Routing fields
		f.Gateway = net.ParseIP(gateway)
		flows = append(flows, f)
	}

	return flows, rows.Err()
}

// Prune deletes flow records older than the retention period.
func (s *SQLiteStore) Prune() (int64, error) {
	cutoff := time.Now().UTC().Add(-s.retention)
	result, err := s.db.Exec("DELETE FROM flows WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	return result.RowsAffected()
}

// pruneLoop runs periodic TTL-based cleanup until stopped.
func (s *SQLiteStore) pruneLoop() {
	defer s.pruneWg.Done()

	ticker := time.NewTicker(s.pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			deleted, err := s.Prune()
			if err != nil {
				logging.Default().Error("SQLite prune error: %v", err)
			} else if deleted > 0 {
				logging.Default().Info("SQLite pruned %d expired flow records", deleted)
			}
		case <-s.stopPrune:
			return
		}
	}
}

// ReportRow holds a single aggregated row from a report query.
type ReportRow struct {
	GroupKey     string
	TotalBytes   uint64
	TotalPackets uint64
	FlowCount    int64
	AvgBytes     float64
}

// TimeSeriesPoint holds one bucket of a time-series aggregation.
type TimeSeriesPoint struct {
	Bucket       string
	TotalBytes   uint64
	TotalPackets uint64
	FlowCount    int64
}

// QueryReport runs an aggregated query over historical flows in SQLite.
// groupBy must be one of: "src_addr", "dst_addr", "protocol", "app_proto",
// "app_category", "dst_port", "src_as", "dst_as".
// Results are sorted by total bytes descending, limited to 100 rows.
func (s *SQLiteStore) QueryReport(start, end time.Time, groupBy string) ([]ReportRow, error) {
	// Whitelist allowed group-by columns to prevent SQL injection.
	allowed := map[string]string{
		"src_addr":     "src_addr",
		"dst_addr":     "dst_addr",
		"protocol":     "protocol",
		"app_proto":    "app_proto",
		"app_category": "app_category",
		"dst_port":     "dst_port",
		"src_as":       "src_as",
		"dst_as":       "dst_as",
	}

	safeColumn, ok := allowed[groupBy]
	if !ok {
		return nil, fmt.Errorf("invalid group-by column: %q", groupBy)
	}

	query := fmt.Sprintf(
		`SELECT %s, SUM(bytes), SUM(packets), COUNT(*), AVG(bytes)
		 FROM flows WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY %s ORDER BY SUM(bytes) DESC LIMIT 100`,
		safeColumn, safeColumn,
	)

	rows, err := s.db.Query(query, start.UTC(), end.UTC())
	if err != nil {
		return nil, fmt.Errorf("report query: %w", err)
	}
	defer rows.Close() // nolint:errcheck // error ignored, rows will be closed when done

	var results []ReportRow //nolint:prealloc // row count unknown before iteration
	for rows.Next() {
		var r ReportRow
		if err := rows.Scan(&r.GroupKey, &r.TotalBytes, &r.TotalPackets, &r.FlowCount, &r.AvgBytes); err != nil {
			return nil, fmt.Errorf("scan report row: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// QueryTimeSeries returns traffic aggregated into time buckets over the given range.
// bucketSec controls bucket width in seconds (e.g. 300 for 5-minute buckets).
func (s *SQLiteStore) QueryTimeSeries(start, end time.Time, bucketSec int) ([]TimeSeriesPoint, error) {
	if bucketSec < 1 {
		bucketSec = 300
	}

	// SQLite's strftime can't parse Go's nanosecond timestamps directly, so we
	// truncate to the first 19 characters (YYYY-MM-DDTHH:MM:SS) for bucketing.
	query := fmt.Sprintf(
		`SELECT datetime(
		    (CAST(strftime('%%s', substr(timestamp, 1, 19)) AS INTEGER) / %d) * %d,
		    'unixepoch') AS bucket,
		  SUM(bytes), SUM(packets), COUNT(*)
		 FROM flows WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY bucket ORDER BY bucket`, bucketSec, bucketSec,
	)

	rows, err := s.db.Query(query, start.UTC(), end.UTC())
	if err != nil {
		return nil, fmt.Errorf("timeseries query: %w", err)
	}
	defer rows.Close() // nolint:errcheck // error ignored, rows will be closed when done

	var points []TimeSeriesPoint //nolint:prealloc // row count unknown before iteration
	for rows.Next() {
		var p TimeSeriesPoint
		if err := rows.Scan(&p.Bucket, &p.TotalBytes, &p.TotalPackets, &p.FlowCount); err != nil {
			return nil, fmt.Errorf("scan timeseries: %w", err)
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// Close stops the pruning goroutine and closes the database.
func (s *SQLiteStore) Close() error {
	close(s.stopPrune)
	s.pruneWg.Wait()
	return s.db.Close()
}
