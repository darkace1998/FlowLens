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

  // Numeric comparison with support for formatted numbers (e.g., "1.5K", "2.3M")
  function compareNumeric(a, b) {
    function parseNumeric(val) {
      if (!val || val === '—' || val === '-' || val === '') return 0;
      
      // Handle formatted bytes like "1.5K", "2.3M", "1.2G"
      const match = val.trim().match(/^([\d.,]+)\s*([KMGT]?)B?$/i);
      if (match) {
        const num = parseFloat(match[1].replace(',', ''));
        const unit = match[2].toUpperCase();
        const multipliers = { K: 1000, M: 1000000, G: 1000000000, T: 1000000000000 };
        return num * (multipliers[unit] || 1);
      }
      
      // Handle plain numbers
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
    
    // Try to parse as ISO date or Unix timestamp
    function parseDate(d) {
      // Try ISO format first
      const iso = Date.parse(d);
      if (!isNaN(iso)) return new Date(iso).getTime();
      
      // Try Unix timestamp (seconds or milliseconds)
      const num = parseFloat(d);
      if (!isNaN(num)) {
        // If it's a reasonable Unix timestamp in seconds
        if (num > 1e10) return num; // milliseconds
        if (num > 1e9) return num * 1000; // seconds
      }
      
      return 0;
    }
    
    const timeA = parseDate(a);
    const timeB = parseDate(b);
    
    return timeA - timeB;
  }

  // Duration comparison (e.g., "1h", "30m", "45s")
  function compareDuration(a, b) {
    function parseDuration(d) {
      if (!d || d === '—' || d === '-') return 0;
      
      const match = d.match(/^([\d.]+)\s*([smhd]?)$/i);
      if (!match) return 0;
      
      const num = parseFloat(match[1]);
      const unit = match[2].toLowerCase();
      const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
      return num * (multipliers[unit] || 1);
    }
    
    const durA = parseDuration(a);
    const durB = parseDuration(b);
    return durA - durB;
  }

  // Main sort function
  function sortTable(header, columnIndex) {
    const table = header.closest('table');
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    if (!tbody) return;
    
    const rows = Array.from(tbody.querySelectorAll('tr'));
    if (rows.length <= 1) return; // No need to sort if 0 or 1 row
    
    // Determine sort type from data attributes
    const isNumeric = header.hasAttribute('data-sort-numeric') || 
                     header.textContent.trim().toLowerCase().includes('bytes') ||
                     header.textContent.trim().toLowerCase().includes('packets') ||
                     header.textContent.trim().toLowerCase().includes('flows') ||
                     header.textContent.trim().toLowerCase().includes('port') ||
                     header.textContent.trim().toLowerCase().includes('count') ||
                     header.textContent.trim().toLowerCase().includes('rtt') ||
                     header.textContent.trim().toLowerCase().includes('jitter') ||
                     header.textContent.trim().toLowerCase().includes('mos') ||
                     header.textContent.trim().toLowerCase().includes('duration') ||
                     header.textContent.trim().toLowerCase().includes('throughput');
    
    const isIP = header.hasAttribute('data-sort-ip') ||
                header.textContent.trim().toLowerCase().includes('ip') ||
                header.textContent.trim().toLowerCase().includes('address') ||
                header.textContent.trim().toLowerCase().includes('gateway');
    
    const isTimestamp = header.hasAttribute('data-sort-timestamp') ||
                       header.textContent.trim().toLowerCase().includes('time') ||
                       header.textContent.trim().toLowerCase().includes('first seen') ||
                       header.textContent.trim().toLowerCase().includes('last seen') ||
                       header.textContent.trim().toLowerCase().includes('started') ||
                       header.textContent.trim().toLowerCase().includes('modified');
    
    const isDuration = header.hasAttribute('data-sort-duration') ||
                      header.textContent.trim().toLowerCase().includes('duration');
    
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
      } else if (isDuration) {
        result = compareDuration(valA, valB);
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
