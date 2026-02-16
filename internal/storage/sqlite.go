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
		db.Close()
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
		mos             REAL NOT NULL DEFAULT 0
	)`
	if _, err := db.Exec(createSQL); err != nil {
		db.Close()
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

	// Create index on timestamp for efficient time-range queries and pruning.
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp)"); err != nil {
		db.Close()
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
		(timestamp, src_addr, dst_addr, src_port, dst_port, protocol,
		 bytes, packets, tcp_flags, tos, input_iface, output_iface,
		 src_as, dst_as, duration_ns, exporter_ip, app_proto, app_category,
		 rtt_us, throughput_bps, retransmissions, out_of_order, packet_loss,
		 jitter_us, mos)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range flows {
		_, err := stmt.Exec(
			f.Timestamp.UTC(),
			model.SafeIPString(f.SrcAddr),
			model.SafeIPString(f.DstAddr),
			f.SrcPort,
			f.DstPort,
			f.Protocol,
			f.Bytes,
			f.Packets,
			f.TCPFlags,
			f.ToS,
			f.InputIface,
			f.OutputIface,
			f.SrcAS,
			f.DstAS,
			f.Duration.Nanoseconds(),
			model.SafeIPString(f.ExporterIP),
			f.AppProto,
			f.AppCat,
			f.RTTMicros,
			f.ThroughputBPS,
			f.Retransmissions,
			f.OutOfOrder,
			f.PacketLoss,
			f.JitterMicros,
			f.MOS,
		)
		if err != nil {
			tx.Rollback()
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
		"jitter_us, mos " +
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
	defer rows.Close()

	var flows []model.Flow
	for rows.Next() {
		var f model.Flow
		var ts time.Time
		var srcAddr, dstAddr, exporterIP string
		var durationNs int64

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
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		f.Timestamp = ts
		f.SrcAddr = net.ParseIP(srcAddr)
		f.DstAddr = net.ParseIP(dstAddr)
		f.ExporterIP = net.ParseIP(exporterIP)
		f.Duration = time.Duration(durationNs)
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
	allowed := map[string]bool{
		"src_addr": true, "dst_addr": true, "protocol": true,
		"app_proto": true, "app_category": true, "dst_port": true,
		"src_as": true, "dst_as": true,
	}
	if !allowed[groupBy] {
		return nil, fmt.Errorf("invalid group-by column: %q", groupBy)
	}

	query := fmt.Sprintf(
		`SELECT %s, SUM(bytes), SUM(packets), COUNT(*), AVG(bytes)
		 FROM flows WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY %s ORDER BY SUM(bytes) DESC LIMIT 100`,
		groupBy, groupBy,
	)

	rows, err := s.db.Query(query, start.UTC(), end.UTC())
	if err != nil {
		return nil, fmt.Errorf("report query: %w", err)
	}
	defer rows.Close()

	var results []ReportRow
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
	defer rows.Close()

	var points []TimeSeriesPoint
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
