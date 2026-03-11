package web

import (
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// FlowService abstracts flow data access so that web handlers are decoupled
// from concrete storage implementations. This makes it easier to test handlers
// in isolation and to swap storage backends in the future.
type FlowService interface {
	// RecentFlows returns flow records from the last duration d, up to limit results.
	// If limit is 0, all matching records are returned.
	RecentFlows(d time.Duration, limit int) ([]model.Flow, error)

	// InsertFlows stores one or more flow records.
	InsertFlows(flows []model.Flow) error

	// FlowCount returns the current number of stored flow records.
	FlowCount() int
}

// ReportService abstracts report/query access for handlers that need
// SQL-backed historical queries.
type ReportService interface {
	// QueryReport runs an aggregate report query.
	QueryReport(start, end time.Time, groupBy string) ([]storage.ReportRow, error)

	// QueryTimeSeries returns time-bucketed flow counts.
	QueryTimeSeries(start, end time.Time, bucketSec int) ([]storage.TimeSeriesPoint, error)
}

// defaultFlowService wraps a RingBuffer to implement FlowService.
type defaultFlowService struct {
	rb *storage.RingBuffer
}

func (s *defaultFlowService) RecentFlows(d time.Duration, limit int) ([]model.Flow, error) {
	return s.rb.Recent(d, limit)
}

func (s *defaultFlowService) InsertFlows(flows []model.Flow) error {
	return s.rb.Insert(flows)
}

func (s *defaultFlowService) FlowCount() int {
	return s.rb.Len()
}

// defaultReportService wraps a SQLiteStore to implement ReportService.
type defaultReportService struct {
	sql *storage.SQLiteStore
}

func (s *defaultReportService) QueryReport(start, end time.Time, groupBy string) ([]storage.ReportRow, error) {
	return s.sql.QueryReport(start, end, groupBy)
}

func (s *defaultReportService) QueryTimeSeries(start, end time.Time, bucketSec int) ([]storage.TimeSeriesPoint, error) {
	return s.sql.QueryTimeSeries(start, end, bucketSec)
}
