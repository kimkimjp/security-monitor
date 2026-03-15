'use strict';

/**
 * Detection rules for suspicious access patterns.
 * Each rule: { id, name, severity, category, test(entry, ipStats?) => boolean }
 *
 * Severity levels: critical, high, medium, low, info
 */

const TRAVERSAL_RE  = /(\.\.|%2e%2e|%252e)/i;
const WP_PATHS_RE   = /\/(wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php|wp-config|wp-cron)/i;
const CONFIG_RE      = /(\/.env|\/\.git|\/\.svn|\/\.htaccess|\/\.htpasswd|\/config\.php|\/database\.yml|\/settings\.py|\/web\.config|\/phpinfo|\/server-status|\/server-info)/i;
const CMDI_RE        = /(\||\$\(|%7c|;|`|%60|\/etc\/passwd|\/etc\/shadow|\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i;
const XSSSQLI_RE    = /(<script|%3cscript|javascript:|onerror=|onload=|union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|%27|%22)/i;
const API_PROBE_RE   = /\/(actuator|swagger|api-docs|graphql|\.well-known|debug|console|admin\/|phpmyadmin|pma|manager\/html|solr|elasticsearch)/i;
const SCANNER_REF_RE = /(zgrab|censys|shodan|masscan|nuclei|dirsearch|gobuster|ffuf|wfuzz|nikto|nessus|qualys)/i;
const SCANNER_UA_RE  = /(curl|wget|python-requests|python-urllib|httplib|nikto|sqlmap|zgrab|censys|masscan|nmap|gobuster|dirsearch|nuclei|ffuf|wfuzz|go-http-client|java\/|libwww-perl|scrapy|httpclient|winhttp|okhttp|axios|node-fetch|scan|bot.*scan)/i;
const KNOWN_BOT_RE   = /(googlebot|bingbot|yandexbot|baiduspider|duckduckbot|slurp|facebookexternalhit|twitterbot|linkedinbot|applebot|mj12bot|ahrefsbot|semrushbot|dotbot|petalbot)/i;

const rules = [
  // --- Protocol anomalies ---
  {
    id: 'PROTO-001',
    name: 'Non-HTTP request',
    severity: 'high',
    category: 'protocol',
    test: (entry) => {
      // Raw request that doesn't look like an HTTP request at all
      if (!entry.rawRequest) return false;
      return !entry.rawRequest.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s/);
    },
  },
  {
    id: 'PROTO-002',
    name: 'Non-HTTP protocol with 400+ status',
    severity: 'high',
    category: 'protocol',
    test: (entry) => {
      if (entry.status < 400) return false;
      return !entry.httpVersion || !entry.httpVersion.startsWith('HTTP/');
    },
  },

  // --- Attack patterns ---
  {
    id: 'ATK-001',
    name: 'WebDAV / PROPFIND probe',
    severity: 'medium',
    category: 'attack',
    test: (entry) => {
      const m = entry.method.toUpperCase();
      return ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'].includes(m);
    },
  },
  {
    id: 'ATK-002',
    name: 'Directory traversal attempt',
    severity: 'critical',
    category: 'attack',
    test: (entry) => TRAVERSAL_RE.test(entry.path) || TRAVERSAL_RE.test(entry.rawRequest),
  },
  {
    id: 'ATK-003',
    name: 'WordPress probe',
    severity: 'medium',
    category: 'attack',
    test: (entry) => WP_PATHS_RE.test(entry.path),
  },
  {
    id: 'ATK-004',
    name: 'Config file probe (.env, .git, etc.)',
    severity: 'high',
    category: 'attack',
    test: (entry) => CONFIG_RE.test(entry.path),
  },
  {
    id: 'ATK-005',
    name: 'Command injection attempt',
    severity: 'critical',
    category: 'attack',
    test: (entry) => CMDI_RE.test(entry.path) || CMDI_RE.test(entry.rawRequest),
  },
  {
    id: 'ATK-006',
    name: 'XSS / SQL injection attempt',
    severity: 'critical',
    category: 'attack',
    test: (entry) => XSSSQLI_RE.test(entry.path) || XSSSQLI_RE.test(entry.rawRequest),
  },
  {
    id: 'ATK-007',
    name: 'API / admin endpoint probe',
    severity: 'medium',
    category: 'attack',
    test: (entry) => API_PROBE_RE.test(entry.path),
  },
  {
    id: 'ATK-008',
    name: 'Scanner tool in referer',
    severity: 'low',
    category: 'attack',
    test: (entry) => entry.referer ? SCANNER_REF_RE.test(entry.referer) : false,
  },

  // --- Rate-based rules ---
  {
    id: 'RATE-001',
    name: 'High request rate (>30 req/60s)',
    severity: 'high',
    category: 'rate',
    test: (entry, ipStats) => {
      if (!ipStats) return false;
      const stats = ipStats.get(entry.ip);
      if (!stats) return false;
      const now = Date.now();
      const windowStart = now - 60000;
      const recentCount = stats.recentTimestamps.filter((t) => t > windowStart).length;
      return recentCount > 30;
    },
  },
  {
    id: 'RATE-002',
    name: 'Excessive 404s (>10 in 5min)',
    severity: 'medium',
    category: 'rate',
    test: (entry, ipStats) => {
      if (!ipStats) return false;
      const stats = ipStats.get(entry.ip);
      if (!stats) return false;
      return stats.recent404Count > 10;
    },
  },

  // --- User-Agent rules ---
  {
    id: 'UA-001',
    name: 'Empty User-Agent',
    severity: 'low',
    category: 'ua',
    test: (entry) => !entry.userAgent || entry.userAgent.trim() === '' || entry.userAgent === '-',
  },
  {
    id: 'UA-002',
    name: 'Known scanner / tool User-Agent',
    severity: 'medium',
    category: 'ua',
    test: (entry) => {
      if (!entry.userAgent) return false;
      return SCANNER_UA_RE.test(entry.userAgent);
    },
  },
  {
    id: 'UA-003',
    name: 'Unknown bot User-Agent',
    severity: 'low',
    category: 'ua',
    test: (entry) => {
      if (!entry.userAgent) return false;
      const ua = entry.userAgent.toLowerCase();
      if (ua.includes('bot') || ua.includes('crawler') || ua.includes('spider')) {
        return !KNOWN_BOT_RE.test(entry.userAgent);
      }
      return false;
    },
  },
];

module.exports = rules;
