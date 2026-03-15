/* ============================================================
   Security Monitor - Internationalization (i18n)
   Supported: ja, en, zh, es, ko
   ============================================================ */

(function () {
  'use strict';

  var translations = {
    // ---- Japanese (default) ----
    ja: {
      // Header
      'app.title': 'セキュリティモニター',
      'status.connecting': '接続中...',
      'status.connected': '接続済み',
      'status.disconnected': '切断',

      // KPI Cards
      'kpi.totalRequests': '総リクエスト数',
      'kpi.period': '(1時間)',
      'kpi.errors4xx': '4xx エラー',
      'kpi.errors5xx': '5xx エラー',
      'kpi.uniqueIps': 'ユニークIP数',

      // Chart Panels
      'chart.timeline': 'リクエスト推移',
      'chart.timelineInterval': '1分間隔',
      'chart.worldmap': 'グローバルアクセスマップ',
      'chart.live': 'ライブ',
      'chart.statusCodes': 'ステータスコード',
      'chart.topIps': 'Top 10 IP',
      'chart.requestsPerMin': 'リクエスト数/分',
      'chart.requests': 'リクエスト数',

      // Alerts
      'alerts.title': '脅威アラート',
      'alerts.notification': 'セキュリティアラート: ',

      // Log Stream
      'log.title': 'ログストリーム',
      'log.autoScroll': '自動スクロール',
      'log.allServices': '全サービス',
      'log.allStatus': '全ステータス',
      'log.filterIp': 'IP検索...',
      'log.filterPath': 'パス検索...',
      'log.clear': 'クリア',

      // Table Headers
      'table.time': '時刻',
      'table.status': 'ステータス',
      'table.method': 'メソッド',
      'table.path': 'パス',
      'table.ip': 'IP',
      'table.country': '国',
      'table.service': 'サービス',

      // Relative Time
      'time.justNow': 'たった今',
      'time.secAgo': '秒前',
      'time.minAgo': '分前',
      'time.hourAgo': '時間前',
      'time.dayAgo': '日前',

      // Tooltip
      'tooltip.requests': 'リクエスト',

      // Severity Descriptions
      'severity.critical': '緊急',
      'severity.critical.desc': '直ちに対応が必要な深刻な脅威です。サーバーへの侵入を試みている可能性があります。',
      'severity.high': '高',
      'severity.high.desc': '重大な脅威です。攻撃者がシステムの脆弱性を探っています。',
      'severity.medium': '中',
      'severity.medium.desc': '注意が必要です。不審なアクティビティが検出されました。',
      'severity.low': '低',
      'severity.low.desc': '情報提供レベルです。通常は即時対応不要ですが、パターンに注意してください。',

      // Rule Descriptions - Protocol
      'rule.PROTO-001': '非HTTPプロトコルの通信',
      'rule.PROTO-001.desc': 'HTTPではないプロトコル（SSH等）でWebポートに接続を試みています。ポートスキャンや誤設定の可能性があります。',
      'rule.PROTO-001.action': '発信元IPを確認し、繰り返す場合はファイアウォールでブロックしてください。',
      'rule.PROTO-002': '不正プロトコル（400エラー）',
      'rule.PROTO-002.desc': 'HTTPとして解釈できないリクエストが送信され、サーバーがエラーを返しました。',
      'rule.PROTO-002.action': '通常は自動的にブロックされます。頻発する場合はIPをブロックしてください。',

      // Rule Descriptions - Attack
      'rule.ATK-001': 'WebDAV探索',
      'rule.ATK-001.desc': 'PROPFINDなどのWebDAVメソッドでサーバーのファイルシステムを探索しています。',
      'rule.ATK-001.action': 'WebDAVを使用していない場合、Nginxで該当メソッドを拒否してください。',
      'rule.ATK-002': 'ディレクトリトラバーサル攻撃',
      'rule.ATK-002.desc': '../ を使ってサーバーの上位ディレクトリにアクセスし、機密ファイルの読み取りを試みています。',
      'rule.ATK-002.action': 'WAFの導入を検討してください。Nginxでパスの正規化が有効か確認してください。',
      'rule.ATK-003': 'WordPress脆弱性スキャン',
      'rule.ATK-003.desc': 'wp-login.phpやxmlrpc.phpなど、WordPressの既知の攻撃ポイントを探索しています。',
      'rule.ATK-003.action': 'WordPressを使用していないため、これらのパスへのアクセスは全て攻撃です。IPブロックを検討してください。',
      'rule.ATK-004': '設定ファイル探索',
      'rule.ATK-004.desc': '.env、.git、phpinfo等の設定ファイルや機密情報へのアクセスを試みています。',
      'rule.ATK-004.action': '機密ファイルがWebから見えないことを確認してください。Nginxで該当パスを明示的に拒否してください。',
      'rule.ATK-005': 'コマンドインジェクション攻撃',
      'rule.ATK-005.desc': 'シェルコマンドをURLに埋め込み、サーバー上でコマンドを実行しようとしています。非常に危険な攻撃です。',
      'rule.ATK-005.action': '入力値のサニタイズを確認してください。WAFの導入を強く推奨します。',
      'rule.ATK-006': 'XSS/SQLインジェクション攻撃',
      'rule.ATK-006.desc': 'スクリプトの埋め込みやSQLクエリの改ざんを試みています。データベースへの不正アクセスやユーザー情報の窃取が目的です。',
      'rule.ATK-006.action': 'パラメータのエスケープ処理を確認してください。プリペアドステートメントを使用してください。',
      'rule.ATK-007': 'API/管理画面探索',
      'rule.ATK-007.desc': '/actuator、/swagger、/admin等の管理エンドポイントを探索しています。',
      'rule.ATK-007.action': '管理画面がある場合、IP制限と認証を確認してください。不要なエンドポイントは無効化してください。',
      'rule.ATK-008': 'スキャナツールのReferer検出',
      'rule.ATK-008.desc': 'Refererヘッダーにセキュリティスキャナツール名が含まれています。自動化された脆弱性スキャンの可能性があります。',
      'rule.ATK-008.action': '自社のセキュリティ診断でなければ、発信元IPを確認してブロックを検討してください。',

      // Rule Descriptions - Rate
      'rule.RATE-001': 'リクエストレート超過',
      'rule.RATE-001.desc': '同一IPから60秒間に30リクエストを超えるアクセスがあります。DDoS攻撃やブルートフォース攻撃の可能性があります。',
      'rule.RATE-001.action': 'Nginxのrate limitingを設定してください。persistent attackerはIPブロックしてください。',
      'rule.RATE-002': '404エラー多発',
      'rule.RATE-002.desc': '同一IPから5分間に10回以上の404エラーが発生しています。存在するパスを総当たりで探索している可能性があります。',
      'rule.RATE-002.action': 'ディレクトリスキャンの兆候です。fail2banの導入を検討してください。',

      // Rule Descriptions - UA
      'rule.UA-001': '空のUser-Agent',
      'rule.UA-001.desc': 'User-Agentが空のリクエストです。ボットやスクリプトからのアクセスの可能性があります。',
      'rule.UA-001.action': '正当なクライアントは通常User-Agentを送信します。他のアラートと併せて判断してください。',
      'rule.UA-002': 'スキャナツールのUser-Agent',
      'rule.UA-002.desc': 'curl、nikto、sqlmap等のセキュリティツールのUser-Agentが検出されました。',
      'rule.UA-002.action': '自社の診断でなければ、不正なスキャンです。IPブロックを検討してください。',
      'rule.UA-003': '不明なボットのUser-Agent',
      'rule.UA-003.desc': 'Google等の既知のボット以外のクローラーが検出されました。',
      'rule.UA-003.action': '多くは無害ですが、robots.txtの設定を確認してください。',

      // Language
      'lang.label': '言語',
    },

    // ---- English ----
    en: {
      'app.title': 'Security Monitor',
      'status.connecting': 'Connecting...',
      'status.connected': 'Connected',
      'status.disconnected': 'Disconnected',

      'kpi.totalRequests': 'Total Requests',
      'kpi.period': '(1h)',
      'kpi.errors4xx': '4xx Errors',
      'kpi.errors5xx': '5xx Errors',
      'kpi.uniqueIps': 'Unique IPs',

      'chart.timeline': 'Request Timeline',
      'chart.timelineInterval': '1min intervals',
      'chart.worldmap': 'Global Access Map',
      'chart.live': 'LIVE',
      'chart.statusCodes': 'Status Codes',
      'chart.topIps': 'Top 10 IPs',
      'chart.requestsPerMin': 'Requests / min',
      'chart.requests': 'Requests',

      'alerts.title': 'Threat Alerts',
      'alerts.notification': 'Security Alert: ',

      'log.title': 'Log Stream',
      'log.autoScroll': 'Auto-scroll',
      'log.allServices': 'All Services',
      'log.allStatus': 'All Status',
      'log.filterIp': 'Filter IP...',
      'log.filterPath': 'Filter Path...',
      'log.clear': 'Clear',

      'table.time': 'Time',
      'table.status': 'Status',
      'table.method': 'Method',
      'table.path': 'Path',
      'table.ip': 'IP',
      'table.country': 'Country',
      'table.service': 'Service',

      'time.justNow': 'just now',
      'time.secAgo': 's ago',
      'time.minAgo': 'm ago',
      'time.hourAgo': 'h ago',
      'time.dayAgo': 'd ago',

      'tooltip.requests': 'requests',

      // Severity Descriptions
      'severity.critical': 'Critical',
      'severity.critical.desc': 'A severe threat requiring immediate attention. Possible server intrusion attempt.',
      'severity.high': 'High',
      'severity.high.desc': 'A significant threat. An attacker is probing for system vulnerabilities.',
      'severity.medium': 'Medium',
      'severity.medium.desc': 'Requires attention. Suspicious activity has been detected.',
      'severity.low': 'Low',
      'severity.low.desc': 'Informational. Usually no immediate action needed, but watch for patterns.',

      'rule.PROTO-001': 'Non-HTTP Protocol',
      'rule.PROTO-001.desc': 'A non-HTTP protocol (e.g., SSH) attempted to connect to the web port. Could be a port scan or misconfiguration.',
      'rule.PROTO-001.action': 'Check the source IP. Block with firewall if repeated.',
      'rule.PROTO-002': 'Invalid Protocol (400 Error)',
      'rule.PROTO-002.desc': 'A request that could not be parsed as HTTP was sent, causing a server error.',
      'rule.PROTO-002.action': 'Usually blocked automatically. Block the IP if frequent.',
      'rule.ATK-001': 'WebDAV Probe',
      'rule.ATK-001.desc': 'PROPFIND and other WebDAV methods are being used to explore the server file system.',
      'rule.ATK-001.action': 'If WebDAV is not used, reject these methods in Nginx.',
      'rule.ATK-002': 'Directory Traversal Attack',
      'rule.ATK-002.desc': 'Attempting to access parent directories using ../ to read sensitive files.',
      'rule.ATK-002.action': 'Consider deploying a WAF. Verify Nginx path normalization is enabled.',
      'rule.ATK-003': 'WordPress Vulnerability Scan',
      'rule.ATK-003.desc': 'Probing known WordPress attack points such as wp-login.php and xmlrpc.php.',
      'rule.ATK-003.action': 'WordPress is not installed, so all such access is an attack. Consider IP blocking.',
      'rule.ATK-004': 'Config File Probe',
      'rule.ATK-004.desc': 'Attempting to access .env, .git, phpinfo, and other configuration/sensitive files.',
      'rule.ATK-004.action': 'Ensure sensitive files are not web-accessible. Explicitly deny these paths in Nginx.',
      'rule.ATK-005': 'Command Injection Attack',
      'rule.ATK-005.desc': 'Attempting to embed shell commands in URLs to execute commands on the server. Highly dangerous.',
      'rule.ATK-005.action': 'Verify input sanitization. Strongly recommend deploying a WAF.',
      'rule.ATK-006': 'XSS / SQL Injection Attack',
      'rule.ATK-006.desc': 'Attempting script injection or SQL query manipulation. Aims to steal data or gain unauthorized access.',
      'rule.ATK-006.action': 'Verify parameter escaping. Use prepared statements for database queries.',
      'rule.ATK-007': 'API / Admin Endpoint Probe',
      'rule.ATK-007.desc': 'Probing for management endpoints such as /actuator, /swagger, /admin.',
      'rule.ATK-007.action': 'If admin panels exist, verify IP restrictions and authentication. Disable unused endpoints.',
      'rule.ATK-008': 'Scanner Tool in Referer',
      'rule.ATK-008.desc': 'The Referer header contains a security scanner tool name. Likely an automated vulnerability scan.',
      'rule.ATK-008.action': 'If not your own security audit, check the source IP and consider blocking.',
      'rule.RATE-001': 'Request Rate Exceeded',
      'rule.RATE-001.desc': 'More than 30 requests in 60 seconds from the same IP. Could be DDoS or brute force.',
      'rule.RATE-001.action': 'Configure Nginx rate limiting. Block persistent attackers by IP.',
      'rule.RATE-002': 'Excessive 404 Errors',
      'rule.RATE-002.desc': 'More than 10 404 errors in 5 minutes from the same IP. Likely directory scanning.',
      'rule.RATE-002.action': 'Signs of directory scanning. Consider deploying fail2ban.',
      'rule.UA-001': 'Empty User-Agent',
      'rule.UA-001.desc': 'Request with an empty User-Agent. Likely from a bot or script.',
      'rule.UA-001.action': 'Legitimate clients normally send a User-Agent. Evaluate alongside other alerts.',
      'rule.UA-002': 'Scanner Tool User-Agent',
      'rule.UA-002.desc': 'User-Agent of curl, nikto, sqlmap, or other security tools detected.',
      'rule.UA-002.action': 'If not your own audit, this is unauthorized scanning. Consider IP blocking.',
      'rule.UA-003': 'Unknown Bot User-Agent',
      'rule.UA-003.desc': 'A crawler not recognized as a known bot (Google, Bing, etc.) was detected.',
      'rule.UA-003.action': 'Usually harmless, but check your robots.txt configuration.',

      'lang.label': 'Language',
    },

    // ---- Chinese (Simplified) ----
    zh: {
      'app.title': '安全监控',
      'status.connecting': '连接中...',
      'status.connected': '已连接',
      'status.disconnected': '已断开',

      'kpi.totalRequests': '总请求数',
      'kpi.period': '(1小时)',
      'kpi.errors4xx': '4xx 错误',
      'kpi.errors5xx': '5xx 错误',
      'kpi.uniqueIps': '独立IP数',

      'chart.timeline': '请求趋势',
      'chart.timelineInterval': '1分钟间隔',
      'chart.worldmap': '全球访问地图',
      'chart.live': '实时',
      'chart.statusCodes': '状态码',
      'chart.topIps': 'Top 10 IP',
      'chart.requestsPerMin': '请求数/分钟',
      'chart.requests': '请求数',

      'alerts.title': '威胁警报',
      'alerts.notification': '安全警报: ',

      'log.title': '日志流',
      'log.autoScroll': '自动滚动',
      'log.allServices': '全部服务',
      'log.allStatus': '全部状态',
      'log.filterIp': '搜索IP...',
      'log.filterPath': '搜索路径...',
      'log.clear': '清除',

      'table.time': '时间',
      'table.status': '状态',
      'table.method': '方法',
      'table.path': '路径',
      'table.ip': 'IP',
      'table.country': '国家',
      'table.service': '服务',

      'time.justNow': '刚刚',
      'time.secAgo': '秒前',
      'time.minAgo': '分钟前',
      'time.hourAgo': '小时前',
      'time.dayAgo': '天前',

      'tooltip.requests': '请求',

      'severity.critical': '紧急',
      'severity.critical.desc': '需要立即处理的严重威胁。可能正在尝试入侵服务器。',
      'severity.high': '高',
      'severity.high.desc': '重大威胁。攻击者正在探测系统漏洞。',
      'severity.medium': '中',
      'severity.medium.desc': '需要关注。检测到可疑活动。',
      'severity.low': '低',
      'severity.low.desc': '信息级别。通常无需立即处理，但请注意模式。',

      'rule.PROTO-001': '非HTTP协议通信',
      'rule.PROTO-001.desc': '非HTTP协议（如SSH）尝试连接Web端口。可能是端口扫描或配置错误。',
      'rule.PROTO-001.action': '检查来源IP，重复出现时使用防火墙封锁。',
      'rule.PROTO-002': '无效协议（400错误）',
      'rule.PROTO-002.desc': '发送了无法解析为HTTP的请求，导致服务器错误。',
      'rule.PROTO-002.action': '通常会自动拦截。频繁出现时封锁IP。',
      'rule.ATK-001': 'WebDAV探测',
      'rule.ATK-001.desc': '使用PROPFIND等WebDAV方法探索服务器文件系统。',
      'rule.ATK-001.action': '如未使用WebDAV，请在Nginx中拒绝这些方法。',
      'rule.ATK-002': '目录遍历攻击',
      'rule.ATK-002.desc': '尝试使用../访问上级目录以读取敏感文件。',
      'rule.ATK-002.action': '考虑部署WAF。确认Nginx路径规范化已启用。',
      'rule.ATK-003': 'WordPress漏洞扫描',
      'rule.ATK-003.desc': '探测wp-login.php、xmlrpc.php等WordPress已知攻击点。',
      'rule.ATK-003.action': '未安装WordPress，此类访问均为攻击。考虑封锁IP。',
      'rule.ATK-004': '配置文件探测',
      'rule.ATK-004.desc': '尝试访问.env、.git、phpinfo等配置和敏感文件。',
      'rule.ATK-004.action': '确保敏感文件不可通过Web访问。在Nginx中明确拒绝这些路径。',
      'rule.ATK-005': '命令注入攻击',
      'rule.ATK-005.desc': '尝试在URL中嵌入Shell命令以在服务器上执行。极其危险。',
      'rule.ATK-005.action': '验证输入过滤。强烈建议部署WAF。',
      'rule.ATK-006': 'XSS/SQL注入攻击',
      'rule.ATK-006.desc': '尝试脚本注入或SQL查询篡改。目的是窃取数据或获取未授权访问。',
      'rule.ATK-006.action': '验证参数转义处理。数据库查询使用预处理语句。',
      'rule.ATK-007': 'API/管理端点探测',
      'rule.ATK-007.desc': '探测/actuator、/swagger、/admin等管理端点。',
      'rule.ATK-007.action': '如有管理面板，确认IP限制和认证。禁用未使用的端点。',
      'rule.ATK-008': 'Referer中检测到扫描工具',
      'rule.ATK-008.desc': 'Referer头包含安全扫描工具名称。可能是自动化漏洞扫描。',
      'rule.ATK-008.action': '如非自身安全审计，检查来源IP并考虑封锁。',
      'rule.RATE-001': '请求速率超限',
      'rule.RATE-001.desc': '同一IP在60秒内发送超过30个请求。可能是DDoS或暴力攻击。',
      'rule.RATE-001.action': '配置Nginx速率限制。封锁持续攻击的IP。',
      'rule.RATE-002': '404错误过多',
      'rule.RATE-002.desc': '同一IP在5分钟内产生超过10次404错误。可能在扫描目录。',
      'rule.RATE-002.action': '目录扫描迹象。考虑部署fail2ban。',
      'rule.UA-001': '空User-Agent',
      'rule.UA-001.desc': 'User-Agent为空的请求。可能来自机器人或脚本。',
      'rule.UA-001.action': '正常客户端通常会发送User-Agent。结合其他警报综合判断。',
      'rule.UA-002': '扫描工具User-Agent',
      'rule.UA-002.desc': '检测到curl、nikto、sqlmap等安全工具的User-Agent。',
      'rule.UA-002.action': '如非自身审计，即为未授权扫描。考虑封锁IP。',
      'rule.UA-003': '未知Bot User-Agent',
      'rule.UA-003.desc': '检测到非已知爬虫（Google、Bing等）的爬虫。',
      'rule.UA-003.action': '通常无害，但请检查robots.txt配置。',

      'lang.label': '语言',
    },

    // ---- Spanish ----
    es: {
      'app.title': 'Monitor de Seguridad',
      'status.connecting': 'Conectando...',
      'status.connected': 'Conectado',
      'status.disconnected': 'Desconectado',

      'kpi.totalRequests': 'Total de Solicitudes',
      'kpi.period': '(1h)',
      'kpi.errors4xx': 'Errores 4xx',
      'kpi.errors5xx': 'Errores 5xx',
      'kpi.uniqueIps': 'IPs Únicos',

      'chart.timeline': 'Línea de Tiempo',
      'chart.timelineInterval': 'Intervalos de 1min',
      'chart.worldmap': 'Mapa de Acceso Global',
      'chart.live': 'EN VIVO',
      'chart.statusCodes': 'Códigos de Estado',
      'chart.topIps': 'Top 10 IPs',
      'chart.requestsPerMin': 'Solicitudes / min',
      'chart.requests': 'Solicitudes',

      'alerts.title': 'Alertas de Amenazas',
      'alerts.notification': 'Alerta de Seguridad: ',

      'log.title': 'Flujo de Registros',
      'log.autoScroll': 'Auto-despl.',
      'log.allServices': 'Todos los Servicios',
      'log.allStatus': 'Todos los Estados',
      'log.filterIp': 'Filtrar IP...',
      'log.filterPath': 'Filtrar Ruta...',
      'log.clear': 'Limpiar',

      'table.time': 'Hora',
      'table.status': 'Estado',
      'table.method': 'Método',
      'table.path': 'Ruta',
      'table.ip': 'IP',
      'table.country': 'País',
      'table.service': 'Servicio',

      'time.justNow': 'ahora',
      'time.secAgo': 's atrás',
      'time.minAgo': 'm atrás',
      'time.hourAgo': 'h atrás',
      'time.dayAgo': 'd atrás',

      'tooltip.requests': 'solicitudes',

      'severity.critical': 'Critico',
      'severity.critical.desc': 'Amenaza grave que requiere atencion inmediata. Posible intento de intrusion.',
      'severity.high': 'Alto',
      'severity.high.desc': 'Amenaza significativa. Un atacante esta buscando vulnerabilidades.',
      'severity.medium': 'Medio',
      'severity.medium.desc': 'Requiere atencion. Se detecto actividad sospechosa.',
      'severity.low': 'Bajo',
      'severity.low.desc': 'Informativo. Normalmente no requiere accion inmediata.',

      'rule.PROTO-001': 'Protocolo no HTTP',
      'rule.PROTO-001.desc': 'Un protocolo no HTTP intento conectarse al puerto web. Posible escaneo de puertos.',
      'rule.PROTO-001.action': 'Verifique la IP de origen. Bloquee con firewall si se repite.',
      'rule.PROTO-002': 'Protocolo invalido (Error 400)',
      'rule.PROTO-002.desc': 'Se envio una solicitud que no pudo interpretarse como HTTP.',
      'rule.PROTO-002.action': 'Normalmente se bloquea automaticamente. Bloquee la IP si es frecuente.',
      'rule.ATK-001': 'Sondeo WebDAV',
      'rule.ATK-001.desc': 'Se usan metodos WebDAV como PROPFIND para explorar el sistema de archivos.',
      'rule.ATK-001.action': 'Si no usa WebDAV, rechace estos metodos en Nginx.',
      'rule.ATK-002': 'Ataque de recorrido de directorios',
      'rule.ATK-002.desc': 'Intenta acceder a directorios superiores usando ../ para leer archivos sensibles.',
      'rule.ATK-002.action': 'Considere implementar un WAF. Verifique la normalizacion de rutas en Nginx.',
      'rule.ATK-003': 'Escaneo de vulnerabilidades WordPress',
      'rule.ATK-003.desc': 'Buscando puntos de ataque conocidos de WordPress como wp-login.php.',
      'rule.ATK-003.action': 'WordPress no esta instalado, todo acceso es un ataque. Considere bloquear la IP.',
      'rule.ATK-004': 'Sondeo de archivos de configuracion',
      'rule.ATK-004.desc': 'Intentando acceder a .env, .git, phpinfo y otros archivos sensibles.',
      'rule.ATK-004.action': 'Asegure que los archivos sensibles no sean accesibles desde la web.',
      'rule.ATK-005': 'Ataque de inyeccion de comandos',
      'rule.ATK-005.desc': 'Intentando ejecutar comandos del sistema embebidos en URLs. Muy peligroso.',
      'rule.ATK-005.action': 'Verifique el saneamiento de entradas. Se recomienda implementar un WAF.',
      'rule.ATK-006': 'Ataque XSS / Inyeccion SQL',
      'rule.ATK-006.desc': 'Intentando inyectar scripts o manipular consultas SQL para robar datos.',
      'rule.ATK-006.action': 'Verifique el escape de parametros. Use sentencias preparadas.',
      'rule.ATK-007': 'Sondeo de endpoints API/Admin',
      'rule.ATK-007.desc': 'Buscando endpoints de administracion como /actuator, /swagger, /admin.',
      'rule.ATK-007.action': 'Verifique restricciones de IP y autenticacion. Desactive endpoints no usados.',
      'rule.ATK-008': 'Herramienta de escaneo en Referer',
      'rule.ATK-008.desc': 'El encabezado Referer contiene el nombre de una herramienta de escaneo.',
      'rule.ATK-008.action': 'Si no es su propia auditoria, verifique la IP y considere bloquearla.',
      'rule.RATE-001': 'Tasa de solicitudes excedida',
      'rule.RATE-001.desc': 'Mas de 30 solicitudes en 60 segundos desde la misma IP. Posible DDoS.',
      'rule.RATE-001.action': 'Configure limitacion de tasa en Nginx. Bloquee atacantes persistentes.',
      'rule.RATE-002': 'Exceso de errores 404',
      'rule.RATE-002.desc': 'Mas de 10 errores 404 en 5 minutos desde la misma IP. Posible escaneo.',
      'rule.RATE-002.action': 'Signos de escaneo de directorios. Considere implementar fail2ban.',
      'rule.UA-001': 'User-Agent vacio',
      'rule.UA-001.desc': 'Solicitud con User-Agent vacio. Probablemente un bot o script.',
      'rule.UA-001.action': 'Los clientes legitimos normalmente envian User-Agent. Evalue con otras alertas.',
      'rule.UA-002': 'User-Agent de herramienta de escaneo',
      'rule.UA-002.desc': 'Se detecto User-Agent de curl, nikto, sqlmap u otras herramientas.',
      'rule.UA-002.action': 'Si no es su auditoria, es un escaneo no autorizado. Considere bloquear la IP.',
      'rule.UA-003': 'User-Agent de bot desconocido',
      'rule.UA-003.desc': 'Se detecto un rastreador no reconocido como bot conocido.',
      'rule.UA-003.action': 'Generalmente inofensivo, pero verifique su robots.txt.',

      'lang.label': 'Idioma',
    },

    // ---- Korean ----
    ko: {
      'app.title': '보안 모니터',
      'status.connecting': '연결 중...',
      'status.connected': '연결됨',
      'status.disconnected': '연결 끊김',

      'kpi.totalRequests': '총 요청 수',
      'kpi.period': '(1시간)',
      'kpi.errors4xx': '4xx 오류',
      'kpi.errors5xx': '5xx 오류',
      'kpi.uniqueIps': '고유 IP 수',

      'chart.timeline': '요청 타임라인',
      'chart.timelineInterval': '1분 간격',
      'chart.worldmap': '글로벌 접속 맵',
      'chart.live': '실시간',
      'chart.statusCodes': '상태 코드',
      'chart.topIps': 'Top 10 IP',
      'chart.requestsPerMin': '요청 수/분',
      'chart.requests': '요청 수',

      'alerts.title': '위협 알림',
      'alerts.notification': '보안 알림: ',

      'log.title': '로그 스트림',
      'log.autoScroll': '자동 스크롤',
      'log.allServices': '전체 서비스',
      'log.allStatus': '전체 상태',
      'log.filterIp': 'IP 검색...',
      'log.filterPath': '경로 검색...',
      'log.clear': '초기화',

      'table.time': '시간',
      'table.status': '상태',
      'table.method': '메서드',
      'table.path': '경로',
      'table.ip': 'IP',
      'table.country': '국가',
      'table.service': '서비스',

      'time.justNow': '방금',
      'time.secAgo': '초 전',
      'time.minAgo': '분 전',
      'time.hourAgo': '시간 전',
      'time.dayAgo': '일 전',

      'tooltip.requests': '요청',

      'severity.critical': '긴급',
      'severity.critical.desc': '즉각적인 대응이 필요한 심각한 위협입니다. 서버 침입 시도 가능성이 있습니다.',
      'severity.high': '높음',
      'severity.high.desc': '중대한 위협입니다. 공격자가 시스템 취약점을 탐색하고 있습니다.',
      'severity.medium': '중간',
      'severity.medium.desc': '주의가 필요합니다. 의심스러운 활동이 감지되었습니다.',
      'severity.low': '낮음',
      'severity.low.desc': '정보성 수준입니다. 즉각적인 조치는 필요 없지만 패턴에 주의하세요.',

      'rule.PROTO-001': '비HTTP 프로토콜 통신',
      'rule.PROTO-001.desc': '비HTTP 프로토콜(SSH 등)이 웹 포트에 연결을 시도했습니다. 포트 스캔 또는 잘못된 설정일 수 있습니다.',
      'rule.PROTO-001.action': '출발지 IP를 확인하고, 반복되면 방화벽으로 차단하세요.',
      'rule.PROTO-002': '잘못된 프로토콜 (400 오류)',
      'rule.PROTO-002.desc': 'HTTP로 파싱할 수 없는 요청이 전송되어 서버 오류가 발생했습니다.',
      'rule.PROTO-002.action': '보통 자동으로 차단됩니다. 빈번하면 IP를 차단하세요.',
      'rule.ATK-001': 'WebDAV 탐색',
      'rule.ATK-001.desc': 'PROPFIND 등 WebDAV 메서드로 서버 파일 시스템을 탐색하고 있습니다.',
      'rule.ATK-001.action': 'WebDAV를 사용하지 않는 경우 Nginx에서 해당 메서드를 거부하세요.',
      'rule.ATK-002': '디렉토리 트래버설 공격',
      'rule.ATK-002.desc': '../를 사용하여 상위 디렉토리에 접근하여 민감한 파일을 읽으려 합니다.',
      'rule.ATK-002.action': 'WAF 도입을 검토하세요. Nginx 경로 정규화가 활성화되었는지 확인하세요.',
      'rule.ATK-003': 'WordPress 취약점 스캔',
      'rule.ATK-003.desc': 'wp-login.php, xmlrpc.php 등 WordPress의 알려진 공격 포인트를 탐색하고 있습니다.',
      'rule.ATK-003.action': 'WordPress가 설치되어 있지 않으므로 모든 접근이 공격입니다. IP 차단을 검토하세요.',
      'rule.ATK-004': '설정 파일 탐색',
      'rule.ATK-004.desc': '.env, .git, phpinfo 등 설정 파일과 민감한 정보에 접근을 시도하고 있습니다.',
      'rule.ATK-004.action': '민감한 파일이 웹에서 접근 불가능한지 확인하세요. Nginx에서 해당 경로를 명시적으로 거부하세요.',
      'rule.ATK-005': '명령어 인젝션 공격',
      'rule.ATK-005.desc': 'URL에 셸 명령어를 삽입하여 서버에서 명령어를 실행하려 합니다. 매우 위험합니다.',
      'rule.ATK-005.action': '입력값 검증을 확인하세요. WAF 도입을 강력히 권장합니다.',
      'rule.ATK-006': 'XSS/SQL 인젝션 공격',
      'rule.ATK-006.desc': '스크립트 삽입이나 SQL 쿼리 조작을 시도하고 있습니다. 데이터 탈취가 목적입니다.',
      'rule.ATK-006.action': '파라미터 이스케이프 처리를 확인하세요. 프리페어드 스테이트먼트를 사용하세요.',
      'rule.ATK-007': 'API/관리 엔드포인트 탐색',
      'rule.ATK-007.desc': '/actuator, /swagger, /admin 등 관리 엔드포인트를 탐색하고 있습니다.',
      'rule.ATK-007.action': '관리 패널이 있다면 IP 제한과 인증을 확인하세요. 사용하지 않는 엔드포인트는 비활성화하세요.',
      'rule.ATK-008': 'Referer에서 스캐너 도구 감지',
      'rule.ATK-008.desc': 'Referer 헤더에 보안 스캐너 도구 이름이 포함되어 있습니다. 자동화된 취약점 스캔입니다.',
      'rule.ATK-008.action': '자체 보안 감사가 아니라면 출발지 IP를 확인하고 차단을 검토하세요.',
      'rule.RATE-001': '요청 속도 초과',
      'rule.RATE-001.desc': '동일 IP에서 60초 내 30건 이상의 요청이 있습니다. DDoS 또는 무차별 대입 공격 가능성이 있습니다.',
      'rule.RATE-001.action': 'Nginx rate limiting을 설정하세요. 지속적인 공격자는 IP를 차단하세요.',
      'rule.RATE-002': '404 오류 다발',
      'rule.RATE-002.desc': '동일 IP에서 5분 내 10회 이상의 404 오류가 발생했습니다. 디렉토리 스캔 가능성이 있습니다.',
      'rule.RATE-002.action': '디렉토리 스캔 징후입니다. fail2ban 도입을 검토하세요.',
      'rule.UA-001': '빈 User-Agent',
      'rule.UA-001.desc': 'User-Agent가 비어있는 요청입니다. 봇이나 스크립트일 가능성이 있습니다.',
      'rule.UA-001.action': '정상 클라이언트는 보통 User-Agent를 보냅니다. 다른 알림과 함께 판단하세요.',
      'rule.UA-002': '스캐너 도구 User-Agent',
      'rule.UA-002.desc': 'curl, nikto, sqlmap 등 보안 도구의 User-Agent가 감지되었습니다.',
      'rule.UA-002.action': '자체 감사가 아니라면 비인가 스캔입니다. IP 차단을 검토하세요.',
      'rule.UA-003': '알 수 없는 봇 User-Agent',
      'rule.UA-003.desc': 'Google, Bing 등 알려진 봇이 아닌 크롤러가 감지되었습니다.',
      'rule.UA-003.action': '대부분 무해하지만 robots.txt 설정을 확인하세요.',

      'lang.label': '언어',
    },
  };

  var LANG_NAMES = {
    ja: '日本語',
    en: 'English',
    zh: '中文',
    es: 'Español',
    ko: '한국어',
  };

  var STORAGE_KEY = 'secmon_lang';
  var currentLang = 'ja';

  function detectLang() {
    var saved = localStorage.getItem(STORAGE_KEY);
    if (saved && translations[saved]) return saved;
    var nav = (navigator.language || '').toLowerCase();
    if (nav.startsWith('ja')) return 'ja';
    if (nav.startsWith('zh')) return 'zh';
    if (nav.startsWith('es')) return 'es';
    if (nav.startsWith('ko')) return 'ko';
    if (nav.startsWith('en')) return 'en';
    return 'ja';
  }

  function t(key) {
    var dict = translations[currentLang] || translations.ja;
    return dict[key] || translations.ja[key] || key;
  }

  function setLang(lang) {
    if (!translations[lang]) return;
    currentLang = lang;
    localStorage.setItem(STORAGE_KEY, lang);
    document.documentElement.lang = lang;
    applyTranslations();
  }

  function getLang() {
    return currentLang;
  }

  function getAvailableLangs() {
    return LANG_NAMES;
  }

  function applyTranslations() {
    // Update all elements with data-i18n attribute
    var els = document.querySelectorAll('[data-i18n]');
    els.forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      el.textContent = t(key);
    });

    // Update all elements with data-i18n-placeholder attribute
    var phs = document.querySelectorAll('[data-i18n-placeholder]');
    phs.forEach(function (el) {
      var key = el.getAttribute('data-i18n-placeholder');
      el.placeholder = t(key);
    });

    // Update page title
    document.title = t('app.title');

    // Dispatch event for JS components to react
    window.dispatchEvent(new CustomEvent('langchange', { detail: { lang: currentLang } }));
  }

  // Initialize
  currentLang = detectLang();

  // Expose global
  window.i18n = {
    t: t,
    setLang: setLang,
    getLang: getLang,
    getAvailableLangs: getAvailableLangs,
    applyTranslations: applyTranslations,
  };

})();
