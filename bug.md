# FlowLens — Bug Report

## Bug #1: Host IP Click Always Filters by Source Address (FIXED)

**Severity:** High  
**Component:** `internal/web/templates/hosts.xhtml`  
**Status:** ✅ Fixed

**Description:**  
On the Active Hosts page, clicking any host IP always navigated to `/flows?src_ip=<IP>`, filtering flows by source address only. Since hosts are tracked from both source *and* destination addresses, clicking a host that appears primarily as a destination would show no matching flows.

**Root Cause:**  
The link in `hosts.xhtml` was hardcoded as `<a href="/flows?src_ip={{.IP}}">`.

**Fix:**  
Added a new `ip` query parameter to the flows filter that matches either source or destination address. Changed the hosts page link to use `/flows?ip={{.IP}}`. Updated `filterFlows()`, `FlowsPageData`, and `flows.xhtml` (including pagination links) to support the new parameter. Added an "IP" input field to the flows filter bar.

---

## Bug #2: Chart.js Visualizations May Not Render (FIXED)

**Severity:** High  
**Component:** `static/style.css`  
**Status:** ✅ Fixed

**Description:**  
The Protocol Distribution (doughnut chart), Top Talkers (bar chart), and Throughput Over Time (line chart) on the dashboard may not render properly. Chart.js with `responsive: true` and `maintainAspectRatio: false` requires the container to have a defined height. The CSS used `max-height` instead of `height`, which can cause Chart.js to mis-calculate the canvas dimensions and render at an incorrect size or not at all.

**Root Cause:**  
`.chart-container` and `.chart-container-sm` in `style.css` used `max-height: 280px` / `max-height: 220px` without an explicit `height` property.

**Fix:**  
Changed `max-height` to `height` for both `.chart-container` (280px) and `.chart-container-sm` (220px).

---

## Bug #3: Flows Table Overflows Without Horizontal Scroll (FIXED)

**Severity:** Medium  
**Component:** `internal/web/templates/flows.xhtml`  
**Status:** ✅ Fixed

**Description:**  
The flows table has 28 columns (Time, Source, Src Port, Country, Destination, Dst Port, Country, Protocol, Application, Category, Bytes, Packets, Throughput, RTT, In Iface, Out Iface, Exporter, Src MAC, Dst MAC, VLAN, EtherType, Retrans, OOO, Loss, Jitter, MOS, Duration, Age). On screens narrower than ~2000px the table overflows the container, and columns like Bytes, Packets, and Throughput may be clipped or invisible. There was no horizontal scroll wrapper.

**Root Cause:**  
The `<table>` element was not wrapped in a `.table-responsive` container, even though the CSS class for it (`overflow-x: auto`) already existed in `style.css`.

**Fix:**  
Wrapped the flows table in `<div class="table-responsive">` to enable horizontal scrolling.

---

## Bug #4: Report Form Select Has Hardcoded White Background (FIXED)

**Severity:** Low  
**Component:** `static/style.css`  
**Status:** ✅ Fixed

**Description:**  
The report form `<select>` element had `background: #fff` hardcoded, which did not respect dark mode. In dark mode, the dropdown appeared as a bright white box.

**Root Cause:**  
`.report-form select` used `background: #fff` instead of the CSS custom property.

**Fix:**  
Changed to `background: var(--input-bg); color: var(--text);` to respect the dark mode theme.

---

## Bug #5: Dashboard Window Displays Raw Go Duration Format (FIXED)

**Severity:** Low  
**Component:** `internal/web/templates/dashboard.xhtml`, `internal/web/templates/hosts.xhtml`  
**Status:** ✅ Fixed

**Description:**  
The dashboard stat card "Flows (10m0s)" and the hosts page "Window: 10m0s" displayed the raw Go `time.Duration` string format (e.g. `10m0s`, `1h30m0s`) instead of a human-friendly format.

**Root Cause:**  
Templates used `{{.Window}}` which calls the default `String()` method on `time.Duration`.

**Fix:**  
Added a `formatDuration` template function that produces compact, human-friendly output (e.g. "10m", "5m 30s", "30s"). Updated dashboard and hosts templates to use `{{formatDuration .Window}}`.

---

## Bug #6: Missing CSS Class for Interface Traffic Bars (FIXED)

**Severity:** Low  
**Component:** `static/style.css`  
**Status:** ✅ Fixed

**Description:**  
The "Traffic by Interface" section in the dashboard uses `class="bar-fill iface"` for progress bars, but the `.bar-fill.iface` CSS class was not defined. Interface bars used the default blue color instead of having a distinct color like other categories (protocol, app, category, AS).

**Root Cause:**  
Missing `.bar-fill.iface` rule in `style.css`.

**Fix:**  
Added `.bar-fill.iface { background: #1b7c83; }` to give interface bars a distinct teal color.

---

## Bug #7: Chart.js Loaded from External CDN (Known Limitation)

**Severity:** Info  
**Component:** `internal/web/templates/dashboard.xhtml`  
**Status:** ⚠️ Known Limitation

**Description:**  
Chart.js is loaded from `https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js`. If the CDN is unreachable (air-gapped network, firewall, or proxy), all three dashboard charts (Protocol Distribution, Top Talkers, Throughput Over Time) will silently fail to render. The JavaScript code checks `if(typeof Chart==='undefined')return;` and gracefully degrades, but provides no visual feedback that charts are missing. Additionally, loading third-party JavaScript from a CDN means that if the CDN or dependency is compromised, malicious code could execute with full privileges in the operator's browser.

**Workaround:**  
The Protocol Breakdown table and other statistics tables still display correct data. A future improvement should bundle Chart.js as a local static asset with Subresource Integrity (SRI) verification, or show a fallback message when Chart.js fails to load.

---

## Bug #8: PPS Shows "0 pps" for Low Packet Rates (FIXED)

**Severity:** Low  
**Component:** `internal/web/handlers.go` — `formatPPS()`  
**Status:** ✅ Fixed

**Description:**  
When the packets-per-second rate is below 0.5, `formatPPS` rounded to `"0 pps"` due to the `"%.0f pps"` format string. This was confusing when there were clearly packets in the window (e.g. 152 packets over 10 minutes = 0.25 pps was shown as "0 pps").

**Root Cause:**  
The fallback format branch used `%.0f`, rounding any sub-integer rate to zero.

**Fix:**  
Added a dedicated sub-1-pps branch that prints two decimals (e.g. `0.25 pps`), and an explicit zero-rate branch. Integer rates ≥ 1 pps still print as `"<n> pps"`. Added a regression test.

---

## Bug #9: DNS Rate/Minute Calculated With Hardcoded 10-Minute Window (FIXED)

**Severity:** Medium  
**Component:** `internal/analysis/dns.go` — `DNSVolume.Analyze`  
**Status:** ✅ Fixed

**Description:**  
The DNS volume analyzer computed flows-per-minute as `dnsFlows / 10.0`, assuming the query window was always 10 minutes. The window is configurable via `AnalysisConfig.QueryWindow`, so any non-10-minute window produced an incorrect rate (and, by extension, wrong advisory severity and threshold comparisons).

**Root Cause:**  
The divisor `10.0` was a literal, not derived from `queryWindow(cfg)`.

**Fix:**  
Replaced the divisor with `queryWindow(cfg).Minutes()` and guarded against a zero/negative window by falling back to 1 minute.

---

## Bug #10: Dashboard Throughput-Over-Time Labels Drift Into the Future (FIXED)

**Severity:** Low  
**Component:** `internal/web/handlers.go` — `buildChartTime()`  
**Status:** ✅ Fixed

**Description:**  
When the dashboard window divided by the bucket count produced a sub-second bucket width, the code clamped `bucketDur` to 1 s but kept `numBuckets = 20`. The label loop then walked 20 × 1 s = 20 s starting at `now - window`, so labels for higher indices were printed with future timestamps and their values stayed empty because the fill loop used the (smaller) real window for `age` filtering.

**Root Cause:**  
`numBuckets` was a compile-time constant not recomputed after `bucketDur` was clamped, and the label/fill paths used `window` instead of `bucketDur × numBuckets`.

**Fix:**  
Recompute `numBuckets = window / bucketDur` (capped at 20) after the clamp and use `effectiveWindow = bucketDur × numBuckets` consistently for labels and age filtering.

---

## Bug #11: Advisory Descriptions Hardcoded "last 10 minutes" (FIXED)

**Severity:** Low  
**Component:** `internal/analysis/toptalkers.go`, `scanner.go`, `dns.go`  
**Status:** ✅ Fixed

**Description:**  
Three analyzers described the evaluation window as "in the last 10 minutes" regardless of the configured `QueryWindow`, misrepresenting the data when operators tune the analysis window.

**Fix:**  
Introduced `formatWindowShort()` in `internal/analysis/engine.go` and replaced each hardcoded literal with the formatted actual query window (e.g. "5m", "1h 30m").

---

## Bug #12: IPFIX NAT-event records pollute flow statistics with zero counters

**Severity:** High (real-world data corruption)
**Component:** `internal/collector/ipfix.go`
**Status:** ✅ Fixed

**Description:**
RFC 8158 NAT-event templates (identified by IE 230 `natEvent`) contain no byte
or packet counters — they record NAT state changes, not traffic. Sophos XG/SG
firewalls and other stateful exporters frequently emit these alongside real
flow templates. FlowLens was decoding each NAT-event record into a `Flow` with
`Bytes=0, Packets=0, Duration=0s`, which poisoned `/api/dashboard` totals,
top-talkers, protocol breakdowns, and rates (observed live: 29 flows, all zero).

**Fix:**
Detect `natEvent` (IE 230) during template parsing and flag the template as
`IsNATEvent`; `decodeIPFIXDataSet` returns no flows for such templates. Also
added handlers for commonly-missing counter IEs so other exporters decode
correctly:
- IE 85 `octetTotalCount`, IE 86 `packetTotalCount` (fill only if delta counters absent)
- IE 231/232 `initiator/responderOctets` → summed into `Bytes` (RFC 5103 biflow)
- IE 298/299 `initiator/responderPackets` → summed into `Packets`
- IE 323 `observationTimeMilliseconds` → used as flow end/start when flow*Milli absent

Tests: `TestDecodeIPFIX_NATEventTemplateSkipped`, `TestDecodeIPFIX_BiflowAndTotalCounters`.

---

## Bug #13: Web UI loses all styling when binary run from arbitrary CWD

**Severity:** Medium (UX/packaging)
**Component:** `internal/web/server.go`, `cmd/flowlens/main.go`, `Dockerfile`
**Status:** ✅ Fixed

**Description:**
The web server resolved `/static/*` via `http.Dir(staticDir)` where
`staticDir` fell back only to `./static` in CWD or `<exe-dir>/static`.
Running the binary from any other working directory silently returned 404s
for `style.css` and `chart.umd.min.js`, producing an unstyled page with no
charts — with no error logged at startup.

**Fix:**
Moved `static/` into `internal/web/static/` and embedded it via
`//go:embed static`. New `staticFileSystem()` helper prefers an on-disk
directory if one exists (for development hot-reload) and falls back to the
embedded FS, making the binary fully self-contained. Updated `Dockerfile`
to stop copying the directory at runtime.
