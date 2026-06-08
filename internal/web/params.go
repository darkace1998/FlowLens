package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// getPageParams extracts and validates "page" and "pageSize" from the request.
func (s *Server) getPageParams(r *http.Request) (page, pageSize int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize = s.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	return page, pageSize
}

// getFlowFilters extracts and trims flow filter parameters from the request.
func (s *Server) getFlowFilters(r *http.Request) (srcIP, dstIP, port, proto, ip string) {
	q := r.URL.Query()
	srcIP = strings.TrimSpace(q.Get("src_ip"))
	dstIP = strings.TrimSpace(q.Get("dst_ip"))
	port = strings.TrimSpace(q.Get("port"))
	proto = strings.TrimSpace(q.Get("protocol"))
	ip = strings.TrimSpace(q.Get("ip"))
	return
}

// getRingBufferWindow returns the configured ring buffer duration,
// or the provided defaultWindow if the configured duration is <= 0.
func (s *Server) getRingBufferWindow(defaultWindow time.Duration) time.Duration {
	window := s.fullCfg.Storage.RingBufferDuration
	if window <= 0 {
		return defaultWindow
	}
	return window
}
