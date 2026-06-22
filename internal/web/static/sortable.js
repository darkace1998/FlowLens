/**
 * FlowLens - Client-side Table Sorting
 * 
 * Provides interactive sorting for all tables with the 'sortable' class.
 * Supports numeric, IP address, timestamp, and string column types.
 */

(function() {
  'use strict';

  // IP address comparison function
  function compareIP(a, b) {
    // Parse IP addresses (IPv4 or IPv6)
    function parseIP(ip) {
      if (!ip || ip === '—' || ip === '-' || ip === '') return [0, 0, 0, 0];
      
      // Handle IPv6 addresses
      if (ip.includes(':')) {
        // For simplicity, we'll compare IPv6 as strings
        // A proper implementation would parse all 8 hextets
        return [0, 0, 0, 1, ip]; // Mark as IPv6 for string comparison
      }
      
      // Parse IPv4
      const parts = ip.split('.').map(parseFloat);
      if (parts.length !== 4) return [0, 0, 0, 0];
      return parts;
    }
    
    const ipA = parseIP(a);
    const ipB = parseIP(b);
    
    // If both are IPv4
    if (ipA.length === 4 && ipB.length === 4) {
      for (let i = 0; i < 4; i++) {
        if (ipA[i] < ipB[i]) return -1;
        if (ipA[i] > ipB[i]) return 1;
      }
      return 0;
    }
    
    // For IPv6 or mixed, use string comparison
    return a.localeCompare(b);
  }

  // Numeric comparison with support for various formats
  function compareNumeric(a, b) {
    function parseNumeric(val) {
      if (!val || val === '—' || val === '-' || val === '') return 0;
      
      val = val.trim();
      
      // Handle formatted bytes with units (B, KB, MB, GB, TB)
      const byteMatch = val.match(/^([\d.,]+)\s*([KMGT]?)B?$/i);
      if (byteMatch) {
        const num = parseFloat(byteMatch[1].replace(',', ''));
        const unit = byteMatch[2].toUpperCase();
        const multipliers = { '': 1, K: 1000, M: 1000000, G: 1000000000, T: 1000000000000 };
        return num * (multipliers[unit] || 1);
      }
      
      // Handle network speeds (bps, Kbps, Mbps, Gbps)
      const speedMatch = val.match(/^([\d.,]+)\s*([KMGT]?)bps$/i);
      if (speedMatch) {
        const num = parseFloat(speedMatch[1].replace(',', ''));
        const unit = speedMatch[2].toUpperCase();
        const multipliers = { '': 1, K: 1000, M: 1000000, G: 1000000000, T: 1000000000000 };
        return num * (multipliers[unit] || 1);
      }
      
      // Handle plain numbers with optional decimal points
      return parseFloat(val.replace(/,/g, '')) || 0;
    }
    
    const numA = parseNumeric(a);
    const numB = parseNumeric(b);
    return numA - numB;
  }

  // Timestamp comparison
  function compareTimestamp(a, b) {
    if (!a || a === '—' || a === '-' || !b || b === '—' || b === '-') {
      return a.toString().localeCompare(b.toString());
    }
    
    // Try to parse as various date formats
    function parseDate(d) {
      d = d.trim();
      
      // Try ISO format with time: "2026-06-22 20:30:45" or "2026-06-22T20:30:45"
      // Also handle "2026-06-22 20:30:45.123456"
      const isoMatch = d.match(/^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$/);
      if (isoMatch) {
        const year = parseInt(isoMatch[1], 10);
        const month = parseInt(isoMatch[2], 10) - 1; // Months are 0-indexed
        const day = parseInt(isoMatch[3], 10);
        const hours = parseInt(isoMatch[4], 10);
        const minutes = parseInt(isoMatch[5], 10);
        const seconds = parseInt(isoMatch[6], 10);
        return new Date(year, month, day, hours, minutes, seconds).getTime();
      }
      
      // Try ISO date only: "2026-06-22"
      const dateMatch = d.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (dateMatch) {
        const year = parseInt(dateMatch[1], 10);
        const month = parseInt(dateMatch[2], 10) - 1;
        const day = parseInt(dateMatch[3], 10);
        return new Date(year, month, day).getTime();
      }
      
      // Try standard JavaScript Date.parse (handles ISO, RFC2822, etc.)
      const parsed = Date.parse(d);
      if (!isNaN(parsed)) return parsed;
      
      // Try Unix timestamp (seconds or milliseconds)
      const num = parseFloat(d);
      if (!isNaN(num)) {
        if (num > 1e10) return num; // milliseconds
        if (num > 1e9) return num * 1000; // seconds
      }
      
      return 0;
    }
    
    const timeA = parseDate(a);
    const timeB = parseDate(b);
    
    // If both are valid timestamps, compare numerically
    if (timeA > 0 && timeB > 0) {
      return timeA - timeB;
    }
    
    // Fallback to string comparison
    return a.toString().localeCompare(b.toString());
  }

  // Duration comparison with support for complex formats
  function compareDuration(a, b) {
    function parseDuration(d) {
      if (!d || d === '—' || d === '-') return 0;
      
      d = d.trim();
      
      // Handle formats like "2m3.42s", "1h2m3.45s", "30.27s"
      // Match all time components: hours, minutes, seconds
      const match = d.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/i);
      if (match) {
        const hours = parseFloat(match[1] || '0');
        const minutes = parseFloat(match[2] || '0');
        const seconds = parseFloat(match[3] || '0');
        return hours * 3600 + minutes * 60 + seconds;
      }
      
      // Handle simple formats like "30m", "2h", "45s"
      const simpleMatch = d.match(/^([\d.]+)\s*([hmsd])$/i);
      if (simpleMatch) {
        const num = parseFloat(simpleMatch[1]);
        const unit = simpleMatch[2].toLowerCase();
        const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
        return num * (multipliers[unit] || 1);
      }
      
      // Try to parse as plain number (seconds)
      const plainNum = parseFloat(d);
      if (!isNaN(plainNum)) {
        return plainNum;
      }
      
      return 0;
    }
    
    const durA = parseDuration(a);
    const durB = parseDuration(b);
    return durA - durB;
  }

  // Age comparison (same as duration, but also handles relative time like "5m ago", "2h ago")
  function compareAge(a, b) {
    function parseAge(d) {
      if (!d || d === '—' || d === '-' || d === '') return 0;
      
      d = d.trim();
      
      // Handle "X ago" format - extract the number and unit
      const agoMatch = d.match(/^([\d.]+)\s*([hmsd]?)\s+ago$/i);
      if (agoMatch) {
        const num = parseFloat(agoMatch[1]);
        const unit = agoMatch[2].toLowerCase();
        const multipliers = { '': 1, s: 1, m: 60, h: 3600, d: 86400 };
        return num * (multipliers[unit] || 1);
      }
      
      // Handle "in X" format (future)
      const inMatch = d.match(/^in\s+([\d.]+)\s*([hmsd]?)$/i);
      if (inMatch) {
        const num = parseFloat(inMatch[1]);
        const unit = inMatch[2].toLowerCase();
        const multipliers = { '': 1, s: 1, m: 60, h: 3600, d: 86400 };
        // Return negative to sort "in X" before "X ago"
        return - (num * (multipliers[unit] || 1));
      }
      
      // Fall back to duration parsing
      return parseDuration(d);
    }
    
    const ageA = parseAge(a);
    const ageB = parseAge(b);
    return ageA - ageB;
  }

  // Main sort function
  function sortTable(header, columnIndex) {
    const table = header.closest('table');
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    if (!tbody) return;
    
    const rows = Array.from(tbody.querySelectorAll('tr'));
    if (rows.length <= 1) return; // No need to sort if 0 or 1 row
    
    // Get header text once for efficiency
    const headerText = header.textContent.trim().toLowerCase();
    
    // Determine sort type from data attributes or header text
    const isNumeric = header.hasAttribute('data-sort-numeric') || 
                     headerText.includes('bytes') ||
                     headerText.includes('packets') ||
                     headerText.includes('flows') ||
                     headerText.includes('port') ||
                     headerText.includes('count') ||
                     headerText.includes('rtt') ||
                     headerText.includes('jitter') ||
                     headerText.includes('mos') ||
                     headerText.includes('throughput') ||
                     headerText.includes('bps') ||
                     headerText.includes('speed') ||
                     headerText.includes('util') ||
                     headerText.includes('rate') ||
                     headerText.includes('share') ||
                     headerText.includes('pct') ||
                     headerText.includes('%') ||
                     headerText.includes('index') ||
                     headerText.includes('asn') ||
                     headerText.includes('value');
    
    const isIP = header.hasAttribute('data-sort-ip') ||
                headerText.includes('ip') ||
                headerText.includes('address') ||
                headerText.includes('gateway') ||
                headerText.includes('src') ||
                headerText.includes('dst') ||
                headerText.includes('exporter') ||
                headerText.includes('host') ||
                headerText.includes('mac');
    
    const isTimestamp = header.hasAttribute('data-sort-timestamp') ||
                       headerText.includes('time') ||
                       headerText.includes('first seen') ||
                       headerText.includes('last seen') ||
                       headerText.includes('started') ||
                       headerText.includes('modified') ||
                       headerText.includes('date') ||
                       headerText.includes('timestamp') ||
                       headerText === 'time';
    
    const isDuration = header.hasAttribute('data-sort-duration') ||
                      headerText.includes('duration') ||
                      headerText.includes('age');
    
    // Get current sort direction and toggle it
    const currentDir = header.getAttribute('data-sort-dir') || 'none';
    let direction;
    if (currentDir === 'none' || currentDir === 'desc') {
      direction = 'asc';
    } else {
      direction = 'desc';
    }
    
    // Remove sort indicators from all headers in this table
    table.querySelectorAll('th').forEach(h => {
      h.removeAttribute('data-sort-dir');
      // Remove sort indicators from header text
      const span = h.querySelector('.sort-indicator');
      if (span) {
        h.removeChild(span);
      }
    });
    
    // Sort rows
    rows.sort((rowA, rowB) => {
      const cellA = rowA.cells[columnIndex];
      const cellB = rowB.cells[columnIndex];
      
      if (!cellA || !cellB) return 0;
      
      const valA = cellA.textContent.trim();
      const valB = cellB.textContent.trim();
      
      let result;
      
      if (isNumeric) {
        result = compareNumeric(valA, valB);
      } else if (isIP) {
        result = compareIP(valA, valB);
      } else if (isTimestamp) {
        result = compareTimestamp(valA, valB);
      } else if (isDuration || headerText === 'age') {
        // Use compareAge for "Age" column specifically as it handles "X ago" format
        result = headerText === 'age' ? compareAge(valA, valB) : compareDuration(valA, valB);
      } else {
        // Default: string comparison
        result = valA.localeCompare(valB, undefined, { numeric: true });
      }
      
      // Reverse for descending
      return direction === 'asc' ? result : -result;
    });
    
    // Re-append sorted rows
    rows.forEach(row => tbody.appendChild(row));
    
    // Update current header with sort indicator
    header.setAttribute('data-sort-dir', direction);
    
    // Add visual sort indicator
    const indicator = document.createElement('span');
    indicator.className = 'sort-indicator';
    indicator.style.marginLeft = '0.25em';
    indicator.style.fontSize = '0.8em';
    indicator.style.opacity = '0.6';
    indicator.textContent = direction === 'asc' ? '▲' : '▼';
    header.appendChild(indicator);
    
    // Store sort state in localStorage for persistence
    try {
      const tableId = table.id || table.className.replace(/\s+/g, '_');
      localStorage.setItem('flowlens-sort-' + tableId + '-' + columnIndex, direction);
    } catch (e) {
      // localStorage might not be available (private browsing, etc.)
    }
  }

  // Initialize sorting for all sortable tables
  function initSortableTables() {
    const tables = document.querySelectorAll('table.sortable');
    
    tables.forEach(table => {
      const headers = table.querySelectorAll('thead th');
      
      headers.forEach((header, index) => {
        // Make header clickable
        header.style.cursor = 'pointer';
        header.style.userSelect = 'none';
        
        // Add hover effect
        header.addEventListener('mouseenter', function() {
          this.style.opacity = '0.8';
        });
        header.addEventListener('mouseleave', function() {
          this.style.opacity = '';
        });
        
        // Add click handler
        header.addEventListener('click', function(e) {
          // Prevent sorting if the click is on a link inside the header
          if (e.target.tagName === 'A') return;
          sortTable(this, index);
        });
        
        // Try to restore saved sort state
        try {
          const tableId = table.id || table.className.replace(/\s+/g, '_');
          const savedDir = localStorage.getItem('flowlens-sort-' + tableId + '-' + index);
          if (savedDir === 'asc' || savedDir === 'desc') {
            header.setAttribute('data-sort-dir', savedDir);
            const indicator = document.createElement('span');
            indicator.className = 'sort-indicator';
            indicator.style.marginLeft = '0.25em';
            indicator.style.fontSize = '0.8em';
            indicator.style.opacity = '0.6';
            indicator.textContent = savedDir === 'asc' ? '▲' : '▼';
            header.appendChild(indicator);
          }
        } catch (e) {
          // localStorage might not be available
        }
      });
    });
  }

  // Auto-initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSortableTables);
  } else {
    initSortableTables();
  }

  // Also expose for manual initialization
  window.initSortableTables = initSortableTables;
  window.sortTable = sortTable;
})();
