# Security Monitor

Real-time Nginx access log security monitoring dashboard with visual threat detection.

![Node.js](https://img.shields.io/badge/Node.js-20+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- **Real-time Log Stream** - Live Nginx access log display with filtering (service, status, IP, path)
- **World Map Visualization** - D3.js global access map with animated arc lines from server to access origins
- **Threat Detection** - 16 built-in rules detecting attacks (directory traversal, SQL injection, command injection, WordPress probes, etc.)
- **KPI Dashboard** - Total requests, 4xx/5xx errors, unique IPs with animated counters
- **Charts** - Request timeline (Chart.js), status code distribution, top 10 IPs
- **GeoIP Lookup** - Country-level geolocation using geoip-lite (local database, no external API)
- **Multi-language** - Japanese, English, Chinese, Spanish, Korean (i18n with browser auto-detection)
- **Alert Descriptions** - Each threat alert includes explanation of the attack and recommended countermeasures
- **SSE (Server-Sent Events)** - Real-time push updates without WebSocket
- **Basic Auth + IP Restriction** - Nginx-level LAN restriction + application-level authentication

## Screenshots

### Dashboard
```
┌─────────────────────────────────────────────┐
│  Security Monitor    ● Connected   [ja ▼]   │
├───────────┬───────────┬───────────┬─────────┤
│ Requests  │  4xx Err  │  5xx Err  │ UniqueIP│
│   1,234   │    89 ↑   │    2 →    │   456   │
├───────────┴───────────┴───────────┴─────────┤
│ [Timeline Chart]       [World Map + Arcs]   │
│ [Status Doughnut]      [Top 10 IPs]         │
├─────────────────────────────────────────────┤
│ Threat Alerts (with descriptions)           │
├─────────────────────────────────────────────┤
│ [Filter: Service|Status|IP|Path]            │
│ Live Log Stream...                          │
└─────────────────────────────────────────────┘
```

## Requirements

- Node.js 18+
- Nginx (with access logs in combined format)
- Read access to Nginx log files

## Installation

```bash
git clone https://github.com/yourusername/security-monitor.git
cd security-monitor
npm install
```

## Configuration

Set environment variables:

```bash
export MONITOR_USER=admin
export MONITOR_PASS=your_secure_password
export MONITOR_PORT=4000                          # default: 4000
export LOG_FILE=/var/log/nginx/access.log          # default
```

## Usage

### Direct

```bash
MONITOR_USER=admin MONITOR_PASS=secret node src/server.js
```

### PM2 (recommended)

```bash
MONITOR_USER=admin MONITOR_PASS=secret pm2 start ecosystem.config.js
pm2 save
```

### Nginx Reverse Proxy

See `nginx.conf.example` for a sample configuration with LAN-only access restriction.

## Architecture

```
Nginx access.log
       │
       │ fs.watch (tail -f style)
       ▼
  Log Parser ─── Regex (combined format)
       │
       ├─→ Detection Engine (16 rules)
       ├─→ GeoIP Lookup (geoip-lite)
       ├─→ Stats Store (in-memory + JSON persistence)
       └─→ SSE Broadcast → Browser Dashboard
```

## Detection Rules

| Category | Rules | Examples |
|----------|-------|---------|
| Protocol | 2 | Non-HTTP requests, invalid protocol |
| Attack | 8 | Directory traversal, SQLi, XSS, command injection, WordPress probes, config file probes |
| Rate | 2 | Request rate >30/min, excessive 404s |
| User-Agent | 3 | Empty UA, scanner tools (nikto, sqlmap), unknown bots |

## Tech Stack

- **Backend**: Node.js, Express, geoip-lite, helmet
- **Frontend**: Vanilla JS, Chart.js, D3.js + TopoJSON
- **Real-time**: Server-Sent Events (SSE)
- **Styling**: CSS (dark theme, responsive)

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard HTML |
| GET | `/api/summary` | KPI summary (1h/6h/24h) |
| GET | `/api/timeline` | Time series data |
| GET | `/api/alerts` | Threat alert list |
| GET | `/api/top/ips` | Top IPs ranking |
| GET | `/api/top/paths` | Top paths ranking |
| GET | `/api/countries` | Country stats with coordinates |
| GET | `/api/events` | SSE stream (access, alert, stats) |
| GET | `/api/health` | Health check (no auth required) |

## License

MIT
