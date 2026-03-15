'use strict';

const fs   = require('fs');
const path = require('path');
const geo  = require('./geo-lookup');

// ---------------------------------------------------------------------------
// Ring Buffer
// ---------------------------------------------------------------------------
class RingBuffer {
  constructor(capacity) {
    this._buf = new Array(capacity);
    this._cap = capacity;
    this._head = 0;   // next write position
    this._size = 0;
  }

  push(item) {
    this._buf[this._head] = item;
    this._head = (this._head + 1) % this._cap;
    if (this._size < this._cap) this._size += 1;
  }

  toArray() {
    if (this._size === 0) return [];
    if (this._size < this._cap) {
      return this._buf.slice(0, this._size);
    }
    // Wrap-around: oldest is at _head, newest at _head - 1
    return [...this._buf.slice(this._head), ...this._buf.slice(0, this._head)];
  }

  getLatest(n) {
    const all = this.toArray();
    if (n >= all.length) return all;
    return all.slice(all.length - n);
  }

  get length() {
    return this._size;
  }
}

// ---------------------------------------------------------------------------
// Service detection helper
// ---------------------------------------------------------------------------
function detectService(urlPath) {
  if (!urlPath) return 'ultrathink-app';
  if (urlPath.startsWith('/convert/') || urlPath === '/convert') return 'xls-converter';
  if (urlPath.startsWith('/limai/') || urlPath === '/limai')     return 'limai-academy';
  if (urlPath.startsWith('/optimize/') || urlPath === '/optimize') return 'file-optimizer';
  return 'ultrathink-app';
}

// ---------------------------------------------------------------------------
// Minute key helper
// ---------------------------------------------------------------------------
function minuteKey(date) {
  const d = date instanceof Date ? date : new Date(date);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${y}-${m}-${day}T${hh}:${mm}`;
}

// ---------------------------------------------------------------------------
// Stats Store
// ---------------------------------------------------------------------------
const DATA_DIR      = path.join(__dirname, '..', 'data');
const SUMMARY_FILE  = path.join(DATA_DIR, 'summary.json');

class StatsStore {
  constructor() {
    this.minuteBuckets  = new Map();   // minuteKey → bucket
    this.ipStats        = new Map();   // ip → stats
    this.recentAlerts   = new RingBuffer(500);
    this.recentLogs     = new RingBuffer(200);
    this.countryStats   = new Map();   // countryCode → { count, name }

    // Pre-computed top-N (refreshed every 30s)
    this.topIPs         = [];
    this.topPaths       = [];
    this.topAttackerIPs = [];

    this._pathCounts    = new Map();
    this._startTime     = Date.now();
    this._totalRequests = 0;
    this._totalAlerts   = 0;

    // 30s recalculation timer
    this._topTimer = setInterval(() => this._recalcTop(), 30000);
    this._topTimer.unref();

    // 5min cleanup timer
    this._cleanupTimer = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    this._cleanupTimer.unref();
  }

  // -----------------------------------------------------------------------
  // Add a parsed log entry
  // -----------------------------------------------------------------------
  addEntry(entry) {
    if (!entry) return;

    this._totalRequests += 1;
    const now = Date.now();
    const service = detectService(entry.path);

    // --- Minute bucket ---
    const mk = minuteKey(entry.timestamp || new Date());
    let bucket = this.minuteBuckets.get(mk);
    if (!bucket) {
      bucket = {
        timestamp: mk,
        total: 0,
        statusCounts: {},
        uniqueIPs: new Set(),
        serviceCounts: {},
        alertCount: 0,
      };
      this.minuteBuckets.set(mk, bucket);
    }
    bucket.total += 1;
    const statusGroup = `${Math.floor(entry.status / 100)}xx`;
    bucket.statusCounts[statusGroup] = (bucket.statusCounts[statusGroup] || 0) + 1;
    bucket.uniqueIPs.add(entry.ip);
    bucket.serviceCounts[service] = (bucket.serviceCounts[service] || 0) + 1;

    // --- IP stats ---
    let ip = this.ipStats.get(entry.ip);
    if (!ip) {
      ip = {
        firstSeen: now,
        lastSeen: now,
        requestCount: 0,
        recentTimestamps: [],
        recent404Count: 0,
        recentPaths: [],
        statusCounts: {},
        alerts: [],
        geoInfo: geo.lookup(entry.ip),
      };
      this.ipStats.set(entry.ip, ip);
    }
    ip.lastSeen = now;
    ip.requestCount += 1;
    ip.recentTimestamps.push(now);
    ip.statusCounts[entry.status] = (ip.statusCounts[entry.status] || 0) + 1;

    // Keep recent timestamps window (last 2 minutes)
    const windowStart = now - 120000;
    if (ip.recentTimestamps.length > 200) {
      ip.recentTimestamps = ip.recentTimestamps.filter((t) => t > windowStart);
    }

    // Track 404s in 5-min window
    if (entry.status === 404) {
      ip.recent404Count += 1;
    }

    // Recent paths (keep last 50)
    ip.recentPaths.push(entry.path);
    if (ip.recentPaths.length > 50) {
      ip.recentPaths = ip.recentPaths.slice(-50);
    }

    // --- Path counts ---
    this._pathCounts.set(entry.path, (this._pathCounts.get(entry.path) || 0) + 1);

    // --- Country stats ---
    const geoInfo = ip.geoInfo;
    const cc = geoInfo.country || 'Unknown';
    let cs = this.countryStats.get(cc);
    if (!cs) {
      cs = { count: 0, name: cc, ll: geoInfo.ll };
      this.countryStats.set(cc, cs);
    }
    cs.count += 1;

    // --- Recent logs ---
    this.recentLogs.push({
      timestamp: entry.timestamp,
      ip: entry.ip,
      method: entry.method,
      path: entry.path,
      status: entry.status,
      bytes: entry.bytes,
      userAgent: entry.userAgent,
      service,
      country: cc,
    });
  }

  // -----------------------------------------------------------------------
  // Add an alert
  // -----------------------------------------------------------------------
  addAlert(alert) {
    if (!alert) return;
    this._totalAlerts += 1;
    this.recentAlerts.push(alert);

    // Update minute bucket alert count
    const mk = minuteKey(alert.timestamp || new Date());
    const bucket = this.minuteBuckets.get(mk);
    if (bucket) bucket.alertCount += 1;

    // Update IP stats
    const ip = this.ipStats.get(alert.ip);
    if (ip) {
      ip.alerts.push({ ruleId: alert.ruleId, severity: alert.severity, timestamp: alert.timestamp });
      if (ip.alerts.length > 100) ip.alerts = ip.alerts.slice(-100);
    }
  }

  // -----------------------------------------------------------------------
  // Recalculate top-N lists
  // -----------------------------------------------------------------------
  _recalcTop() {
    // Top IPs by request count
    const ipArr = Array.from(this.ipStats.entries())
      .map(([ip, s]) => ({ ip, count: s.requestCount, country: s.geoInfo.country, lastSeen: s.lastSeen }))
      .sort((a, b) => b.count - a.count);
    this.topIPs = ipArr.slice(0, 20);

    // Top paths
    const pathArr = Array.from(this._pathCounts.entries())
      .map(([p, count]) => ({ path: p, count }))
      .sort((a, b) => b.count - a.count);
    this.topPaths = pathArr.slice(0, 20);

    // Top attacker IPs (by alert count)
    const attackerArr = Array.from(this.ipStats.entries())
      .filter(([, s]) => s.alerts.length > 0)
      .map(([ip, s]) => ({ ip, alertCount: s.alerts.length, requestCount: s.requestCount, country: s.geoInfo.country }))
      .sort((a, b) => b.alertCount - a.alertCount);
    this.topAttackerIPs = attackerArr.slice(0, 20);
  }

  // -----------------------------------------------------------------------
  // Get summary KPIs
  // -----------------------------------------------------------------------
  getSummary(range) {
    const now = Date.now();
    const ranges = { '1h': 3600000, '6h': 21600000, '24h': 86400000 };
    const windowMs = ranges[range] || ranges['1h'];
    const windowStart = now - windowMs;

    let totalReqs = 0;
    let totalAlerts = 0;
    const statusTotals = {};
    const uniqueIPs = new Set();
    const serviceTotals = {};

    for (const [, bucket] of this.minuteBuckets) {
      const bucketTime = new Date(bucket.timestamp).getTime();
      if (bucketTime < windowStart) continue;
      totalReqs += bucket.total;
      totalAlerts += bucket.alertCount;
      for (const [k, v] of Object.entries(bucket.statusCounts)) {
        statusTotals[k] = (statusTotals[k] || 0) + v;
      }
      for (const ip of bucket.uniqueIPs) uniqueIPs.add(ip);
      for (const [k, v] of Object.entries(bucket.serviceCounts)) {
        serviceTotals[k] = (serviceTotals[k] || 0) + v;
      }
    }

    return {
      range,
      totalRequests: totalReqs,
      totalAlerts,
      uniqueIPCount: uniqueIPs.size,
      statusCounts: statusTotals,
      serviceCounts: serviceTotals,
      uptimeMs: now - this._startTime,
      allTimeRequests: this._totalRequests,
      allTimeAlerts: this._totalAlerts,
    };
  }

  // -----------------------------------------------------------------------
  // Get timeline data
  // -----------------------------------------------------------------------
  getTimeline(range) {
    const now = Date.now();
    const ranges = { '1h': 3600000, '6h': 21600000, '24h': 86400000 };
    const windowMs = ranges[range] || ranges['1h'];
    const windowStart = now - windowMs;

    const timeline = [];
    for (const [key, bucket] of this.minuteBuckets) {
      const bucketTime = new Date(key).getTime();
      if (bucketTime < windowStart) continue;
      timeline.push({
        timestamp: key,
        total: bucket.total,
        statusCounts: bucket.statusCounts,
        uniqueIPs: bucket.uniqueIPs.size,
        serviceCounts: bucket.serviceCounts,
        alertCount: bucket.alertCount,
      });
    }

    timeline.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return timeline;
  }

  // -----------------------------------------------------------------------
  // Country stats (with lat/lon)
  // -----------------------------------------------------------------------
  getCountryStats() {
    return Array.from(this.countryStats.entries())
      .map(([code, s]) => ({ code, name: s.name, count: s.count, ll: s.ll }))
      .sort((a, b) => b.count - a.count);
  }

  // -----------------------------------------------------------------------
  // Cleanup old data (>24h)
  // -----------------------------------------------------------------------
  cleanup() {
    const cutoff = Date.now() - 86400000;

    // Minute buckets
    for (const [key] of this.minuteBuckets) {
      if (new Date(key).getTime() < cutoff) {
        this.minuteBuckets.delete(key);
      }
    }

    // IP stats: remove IPs not seen in 24h
    for (const [ip, stats] of this.ipStats) {
      if (stats.lastSeen < cutoff) {
        this.ipStats.delete(ip);
      } else {
        // Trim old timestamps
        stats.recentTimestamps = stats.recentTimestamps.filter((t) => t > cutoff);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Persist / Restore
  // -----------------------------------------------------------------------
  persist() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }

      const data = {
        savedAt: new Date().toISOString(),
        totalRequests: this._totalRequests,
        totalAlerts: this._totalAlerts,
        startTime: this._startTime,
        countryStats: Array.from(this.countryStats.entries()),
        topIPs: this.topIPs,
        topPaths: this.topPaths,
        topAttackerIPs: this.topAttackerIPs,
      };

      fs.writeFileSync(SUMMARY_FILE, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
      console.error('[Store] Persist error:', err.message);
    }
  }

  restore() {
    try {
      if (!fs.existsSync(SUMMARY_FILE)) return;
      const raw = fs.readFileSync(SUMMARY_FILE, 'utf8');
      const data = JSON.parse(raw);

      if (data.countryStats) {
        for (const [code, info] of data.countryStats) {
          this.countryStats.set(code, info);
        }
      }
      if (data.totalRequests) this._totalRequests = data.totalRequests;
      if (data.totalAlerts)   this._totalAlerts = data.totalAlerts;
      if (data.startTime)     this._startTime = data.startTime;

      console.log(`[Store] Restored from ${SUMMARY_FILE}`);
    } catch (err) {
      console.error('[Store] Restore error:', err.message);
    }
  }

  // -----------------------------------------------------------------------
  // Teardown
  // -----------------------------------------------------------------------
  destroy() {
    clearInterval(this._topTimer);
    clearInterval(this._cleanupTimer);
  }
}

module.exports = { RingBuffer, StatsStore, detectService };
