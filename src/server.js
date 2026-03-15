'use strict';

const express         = require('express');
const helmet          = require('helmet');
const path            = require('path');
const { parseLine }   = require('./log-parser');
const DetectionEngine = require('./detection-engine');
const { StatsStore, detectService, getServiceConfig } = require('./store');
const LogWatcher      = require('./log-watcher');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const PORT     = parseInt(process.env.MONITOR_PORT || '4000', 10);
const LOG_FILE = process.env.LOG_FILE || '/var/log/nginx/access.log';
const AUTH_USER = process.env.MONITOR_USER;
const AUTH_PASS = process.env.MONITOR_PASS;

if (!AUTH_USER || !AUTH_PASS) {
  console.error('[SecurityMonitor] FATAL: MONITOR_USER and MONITOR_PASS environment variables are required.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Initialise components
// ---------------------------------------------------------------------------
const app      = express();
const store    = new StatsStore();
const engine   = new DetectionEngine();
const watcher  = new LogWatcher();

// SSE client management
const sseClients = new Set();

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: false,  // allow inline scripts in dashboard
}));

// Basic Auth
app.use((req, res, next) => {
  // Allow /api/health without auth for monitoring tools
  if (req.path === '/api/health') return next();

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Security Monitor"');
    return res.status(401).send('Authentication required');
  }

  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (user !== AUTH_USER || pass !== AUTH_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Security Monitor"');
    return res.status(401).send('Invalid credentials');
  }

  next();
});

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

const VALID_RANGES = ['1h', '6h', '24h'];

app.get('/api/summary', (req, res) => {
  const range = VALID_RANGES.includes(req.query.range) ? req.query.range : '1h';
  const raw = store.getSummary(range);
  res.json({
    ...raw,
    totalRequests: raw.totalRequests,
    errors4xx: raw.statusCounts['4xx'] || 0,
    errors5xx: raw.statusCounts['5xx'] || 0,
    uniqueIps: raw.uniqueIPCount,
    statusCodes: raw.statusCounts,
  });
});

app.get('/api/timeline', (req, res) => {
  const range = VALID_RANGES.includes(req.query.range) ? req.query.range : '1h';
  const raw = store.getTimeline(range);
  res.json(raw.map(d => ({
    time: d.timestamp,
    t: d.timestamp,
    count: d.total,
    y: d.total,
    ...d,
  })));
});

app.get('/api/alerts', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 500);
  const alerts = store.recentAlerts.getLatest(limit).map(a => ({
    ...a,
    title: a.ruleName,
    type: a.ruleId,
  }));
  res.json(alerts);
});

app.get('/api/top/ips', (_req, res) => {
  const data = store.topIPs.map(d => ({
    ...d,
    countryCode: d.country,
    suspicious: (store.ipStats.get(d.ip)?.alerts?.length || 0) > 0,
  }));
  res.json(data);
});

app.get('/api/top/paths', (_req, res) => {
  res.json(store.topPaths);
});

app.get('/api/countries', (_req, res) => {
  const raw = store.getCountryStats();
  res.json(raw.map(c => ({
    ...c,
    countryCode: c.code,
    country: c.name,
    lat: c.ll?.[0] || 0,
    lng: c.ll?.[1] || 0,
  })));
});

app.get('/api/config/services', (_req, res) => {
  const cfg = getServiceConfig();
  res.json({ services: cfg.services || [], defaultService: cfg.defaultService || 'default' });
});

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    totalRequests: store._totalRequests,
    totalAlerts: store._totalAlerts,
    memoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  });
});

// ---------------------------------------------------------------------------
// SSE Endpoint
// ---------------------------------------------------------------------------
app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',   // disable Nginx buffering
  });

  res.write('event: connected\ndata: {"status":"connected"}\n\n');

  const client = { res };
  sseClients.add(client);

  req.on('close', () => {
    sseClients.delete(client);
  });
});

function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.res.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

// Periodic stats broadcast (every 5 seconds)
const statsInterval = setInterval(() => {
  if (sseClients.size > 0) {
    const raw = store.getSummary('1h');
    broadcastSSE('stats', {
      ...raw,
      errors4xx: raw.statusCounts['4xx'] || 0,
      errors5xx: raw.statusCounts['5xx'] || 0,
      uniqueIps: raw.uniqueIPCount,
      statusCodes: raw.statusCounts,
    });
  }
}, 5000);
statsInterval.unref();

// ---------------------------------------------------------------------------
// Log processing pipeline
// ---------------------------------------------------------------------------
watcher.on('line', (line) => {
  const entry = parseLine(line);
  if (!entry) return;

  // Update store
  store.addEntry(entry);

  // Run detection
  const alerts = engine.analyze(entry, store.ipStats);
  for (const alert of alerts) {
    store.addAlert(alert);
    broadcastSSE('alert', { ...alert, title: alert.ruleName, type: alert.ruleId });
  }

  // Broadcast access event (throttled: only if SSE clients connected)
  if (sseClients.size > 0) {
    const geoInfo = store.ipStats.get(entry.ip)?.geoInfo;
    const service = detectService(entry.path);
    broadcastSSE('access', {
      timestamp: entry.timestamp,
      ip: entry.ip,
      method: entry.method,
      path: entry.path,
      status: entry.status,
      userAgent: entry.userAgent,
      service,
      country: geoInfo?.country || '',
      geoInfo: geoInfo ? {
        countryCode: geoInfo.country,
        country: geoInfo.country,
        lat: geoInfo.ll?.[0] || 0,
        lng: geoInfo.ll?.[1] || 0,
      } : null,
    });
  }
});

watcher.on('error', (err) => {
  console.error('[Server] LogWatcher error:', err.message);
});

// ---------------------------------------------------------------------------
// Persistence timer (every 5 minutes)
// ---------------------------------------------------------------------------
const persistInterval = setInterval(() => {
  store.persist();
}, 5 * 60 * 1000);
persistInterval.unref();

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
store.restore();

const server = app.listen(PORT, () => {
  console.log(`[SecurityMonitor] Listening on port ${PORT}`);
  console.log(`[SecurityMonitor] Watching log file: ${LOG_FILE}`);

  // Start watching after server is up
  watcher.watch(LOG_FILE);
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------
function shutdown(signal) {
  console.log(`\n[SecurityMonitor] Received ${signal}, shutting down...`);

  // Close SSE connections
  for (const client of sseClients) {
    try { client.res.end(); } catch { /* ignore */ }
  }
  sseClients.clear();

  // Stop timers
  clearInterval(statsInterval);
  clearInterval(persistInterval);

  // Stop watcher
  watcher.close();

  // Persist final state
  store.persist();
  store.destroy();

  // Close HTTP server
  server.close(() => {
    console.log('[SecurityMonitor] Server closed.');
    process.exit(0);
  });

  // Force exit after 5 seconds
  setTimeout(() => {
    console.error('[SecurityMonitor] Forced exit after timeout.');
    process.exit(1);
  }, 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

module.exports = { app, server };
