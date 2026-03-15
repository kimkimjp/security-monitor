# Security Monitor

Real-time Nginx access log security monitoring dashboard with visual threat detection.

Nginxアクセスログをリアルタイムで監視するセキュリティダッシュボード。

![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Languages](https://img.shields.io/badge/i18n-ja%20%7C%20en%20%7C%20zh%20%7C%20es%20%7C%20ko-orange)

---

## Features / 機能

- **Real-time Log Stream** / **リアルタイムログ表示** - SSE-based live log viewer with filtering by service, status code, IP, and path
- **World Map Visualization** / **世界地図表示** - D3.js global map with animated arc lines from your server to access origins
- **16 Threat Detection Rules** / **16種の脅威検知ルール** - Directory traversal, SQL injection, XSS, command injection, WordPress probes, and more
- **KPI Dashboard** / **KPIダッシュボード** - Total requests, 4xx/5xx errors, unique IPs with animated counters
- **Charts** / **チャート** - Request timeline, status code distribution, top 10 IPs (Chart.js)
- **GeoIP Lookup** / **GeoIP検索** - Country-level geolocation using local database (no external API calls)
- **Multi-language** / **多言語対応** - Japanese, English, Chinese, Spanish, Korean
- **Alert Descriptions** / **アラート説明** - Each alert includes threat explanation and recommended countermeasures in all languages
- **Configurable Services** / **サービス設定** - Define your own services via `config.json` for path-based routing

---

## Quick Start / クイックスタート

### 1. Clone & Install / クローン & インストール

```bash
git clone https://github.com/kimkimjp/security-monitor.git
cd security-monitor
npm install
```

### 2. Configure / 設定

```bash
# Copy the example config
# サンプル設定ファイルをコピー
cp config.example.json config.json
```

Edit `config.json` to match your environment:
`config.json` を自分の環境に合わせて編集:

```json
{
  "services": [
    { "name": "my-app", "prefix": "/", "color": "#3b82f6" },
    { "name": "my-api", "prefix": "/api/", "color": "#8b5cf6" }
  ],
  "defaultService": "my-app",
  "server": {
    "port": 4000,
    "logFile": "/var/log/nginx/access.log"
  }
}
```

| Field | Description / 説明 |
|-------|-------------------|
| `services[].name` | Display name for the service / サービスの表示名 |
| `services[].prefix` | URL path prefix to match / マッチするURLパスのプレフィックス |
| `services[].color` | Hex color for the dashboard badge / ダッシュボードのバッジカラー |
| `defaultService` | Fallback service name / デフォルトのサービス名 |
| `server.port` | Dashboard server port / ダッシュボードのポート番号 |
| `server.logFile` | Path to Nginx access log / Nginxアクセスログのパス |

### 3. Set Credentials / 認証設定

```bash
# Required environment variables
# 必須の環境変数
export MONITOR_USER=admin
export MONITOR_PASS=your_secure_password_here
```

### 4. Run / 起動

```bash
# Direct
MONITOR_USER=admin MONITOR_PASS=secret node src/server.js

# PM2 (recommended / 推奨)
MONITOR_USER=admin MONITOR_PASS=secret pm2 start ecosystem.config.js
pm2 save
```

### 5. Access / アクセス

Open in browser / ブラウザで開く: `http://localhost:4000`

---

## Nginx Reverse Proxy Setup / Nginxリバースプロキシ設定

For production, serve behind Nginx with LAN-only access restriction:
本番環境では、NginxでLAN内のみアクセス可能にすることを推奨:

```nginx
# Add to your Nginx server block
# Nginxのserverブロックに追加

location /monitor/ {
    # Restrict to local network only / ローカルネットワークのみ許可
    allow 192.168.0.0/16;
    allow 10.0.0.0/8;
    allow 127.0.0.1;
    deny all;

    proxy_pass http://127.0.0.1:4000/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;        # Required for SSE / SSEに必須
    proxy_cache off;
    proxy_read_timeout 86400s;  # Long timeout for SSE / SSEの長時間接続用
}
```

Then test and reload:
設定をテストしてリロード:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## Log File Permission / ログファイルの権限

The application needs read access to Nginx log files. Typical setup:
アプリケーションにはNginxログファイルの読み取り権限が必要です:

```bash
# Add your user to the adm group (Nginx logs are usually owned by www-data:adm)
# admグループにユーザーを追加（Nginxログは通常 www-data:adm の所有）
sudo usermod -aG adm $(whoami)
# Log out and back in for the change to take effect
# 変更を反映するために再ログインしてください
```

---

## Architecture / アーキテクチャ

```
Nginx access.log
       │
       │ fs.watch (tail -f style)
       ▼
  Log Parser ─── Regex (Nginx combined format)
       │
       ├─→ Detection Engine (16 rules)
       ├─→ GeoIP Lookup (geoip-lite, local DB)
       ├─→ Stats Store (in-memory + JSON persistence)
       └─→ SSE Broadcast → Browser Dashboard
```

### Project Structure / プロジェクト構成

```
security-monitor/
├── config.example.json    # Service configuration template / サービス設定テンプレート
├── config.json            # Your local config (gitignored) / ローカル設定 (git除外)
├── ecosystem.config.js    # PM2 configuration / PM2設定
├── nginx.conf.example     # Nginx reverse proxy example / Nginxリバースプロキシ例
├── package.json
├── src/
│   ├── server.js          # Express + SSE server / Express + SSEサーバー
│   ├── log-parser.js      # Nginx combined format parser / Nginxログパーサー
│   ├── log-watcher.js     # File watcher (tail -f) / ファイル監視
│   ├── detection-engine.js # Threat detection / 脅威検知エンジン
│   ├── rules.js           # 16 detection rules / 16種の検知ルール
│   ├── geo-lookup.js      # GeoIP wrapper / GeoIPラッパー
│   └── store.js           # In-memory stats store / メモリ内統計ストア
└── public/
    ├── index.html          # Dashboard HTML
    ├── css/dashboard.css   # Dark theme styles / ダークテーマCSS
    └── js/
        ├── dashboard.js    # Charts, map, SSE client / チャート、地図、SSE
        └── i18n.js         # 5-language translations / 5言語翻訳
```

---

## Detection Rules / 検知ルール

| Category / カテゴリ | Count / 数 | Examples / 例 |
|---------------------|-----------|---------------|
| Protocol / プロトコル | 2 | Non-HTTP requests, invalid protocol / 非HTTPリクエスト |
| Attack / 攻撃 | 8 | Directory traversal, SQLi, XSS, command injection, WordPress probes / ディレクトリトラバーサル、SQLi、XSS等 |
| Rate / レート | 2 | >30 req/min, excessive 404s / リクエスト過多、404多発 |
| User-Agent / UA | 3 | Empty UA, scanner tools, unknown bots / 空UA、スキャナ、不明ボット |

---

## API Endpoints / APIエンドポイント

All endpoints require Basic Auth except `/api/health`.
`/api/health` 以外は全てBasic認証が必要です。

| Method | Path | Description / 説明 |
|--------|------|-------------------|
| GET | `/` | Dashboard UI / ダッシュボード画面 |
| GET | `/api/summary` | KPI summary / KPIサマリー |
| GET | `/api/timeline?range=1h` | Time series data / 時系列データ |
| GET | `/api/alerts?limit=50` | Threat alerts / 脅威アラート一覧 |
| GET | `/api/top/ips` | Top IPs ranking / トップIPランキング |
| GET | `/api/top/paths` | Top paths ranking / トップパスランキング |
| GET | `/api/countries` | Country stats with coordinates / 国別統計（座標付き） |
| GET | `/api/config/services` | Service configuration / サービス設定 |
| GET | `/api/events` | SSE stream (access, alert, stats) / SSEストリーム |
| GET | `/api/health` | Health check (no auth) / ヘルスチェック（認証不要） |

---

## Tech Stack / 技術スタック

| Layer / 層 | Technology / 技術 |
|-----------|------------------|
| Backend | Node.js, Express, helmet |
| Log Monitoring / ログ監視 | fs.watch + readline (tail -f) |
| GeoIP | geoip-lite (local MaxMind DB) |
| Real-time / リアルタイム | Server-Sent Events (SSE) |
| Frontend | Vanilla JS, Chart.js, D3.js, TopoJSON |
| Styling | CSS (dark theme, responsive) |
| Auth / 認証 | HTTP Basic Auth |

---

## Environment Variables / 環境変数

| Variable | Required / 必須 | Description / 説明 |
|----------|----------------|-------------------|
| `MONITOR_USER` | Yes | Dashboard login username / ダッシュボードのユーザー名 |
| `MONITOR_PASS` | Yes | Dashboard login password / ダッシュボードのパスワード |
| `MONITOR_PORT` | No | Server port (default: 4000) / ポート番号 |
| `LOG_FILE` | No | Nginx log path (default: /var/log/nginx/access.log) / ログファイルパス |

---

## Security Considerations / セキュリティに関する注意

- **Do not expose the dashboard to the internet.** Use Nginx IP restriction or VPN.
  **ダッシュボードをインターネットに公開しないでください。** Nginx IP制限またはVPNを使用してください。
- Credentials are passed via environment variables, never hardcoded.
  認証情報は環境変数で渡し、ハードコードしません。
- `config.json` is gitignored to prevent leaking service configurations.
  `config.json` はgitignoreに含まれ、サービス設定の漏洩を防ぎます。
- The `/api/health` endpoint is the only one accessible without authentication.
  `/api/health` は認証なしでアクセスできる唯一のエンドポイントです。

---

## License / ライセンス

MIT

---

## Contributing / コントリビューション

Pull requests are welcome. For major changes, please open an issue first.
プルリクエストを歓迎します。大きな変更は、まずissueを作成してください。
