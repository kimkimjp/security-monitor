/* ============================================================
   Security Monitor - Dashboard JavaScript
   ============================================================ */

(function () {
  'use strict';

  // ---- Constants ----
  const TOKYO = [139.6503, 35.6762]; // [lng, lat]
  const MAX_LOG_ROWS = 500;
  const MAX_ALERTS = 50;
  const TOAST_DURATION = 5000;

  // ---- i18n shortcut ----
  function t(key) { return window.i18n ? window.i18n.t(key) : key; }

  // ---- State ----
  const state = {
    logs: [],
    alerts: [],
    countries: new Map(),   // code -> { name, lat, lng, count, suspicious }
    prevKpi: {},
    autoScroll: true,
    filters: { service: '', status: '', ip: '', path: '' },
  };

  // ---- Utility Functions ----

  function countryCodeToFlag(code) {
    if (!code || code.length !== 2) return '';
    const cp = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
    return String.fromCodePoint(...cp);
  }

  function formatNumber(n) {
    if (n == null) return '0';
    return Number(n).toLocaleString();
  }

  function relativeTime(dateStr) {
    const now = Date.now();
    const then = new Date(dateStr).getTime();
    const diffSec = Math.floor((now - then) / 1000);
    if (diffSec < 5) return t('time.justNow');
    if (diffSec < 60) return diffSec + t('time.secAgo');
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return diffMin + t('time.minAgo');
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return diffHr + t('time.hourAgo');
    return Math.floor(diffHr / 24) + t('time.dayAgo');
  }

  function statusClass(code) {
    const n = Number(code);
    if (n < 300) return 's2xx';
    if (n < 400) return 's3xx';
    if (n < 500) return 's4xx';
    return 's5xx';
  }

  // Service config loaded from API
  const serviceColors = {};

  function serviceClass(svc) {
    return (svc || '').toLowerCase().replace(/[^a-z0-9]/g, '-');
  }

  function getServiceColor(svc) {
    return serviceColors[(svc || '').toLowerCase()] || '#64748b';
  }

  function shortTime(dateStr) {
    const d = new Date(dateStr);
    return d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // Animated count-up
  function animateValue(el, start, end, duration) {
    const startTime = performance.now();
    const diff = end - start;
    if (diff === 0) { el.textContent = formatNumber(end); return; }
    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = formatNumber(Math.round(start + diff * eased));
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---- Clock ----
  function updateClock() {
    const el = document.getElementById('header-clock');
    const now = new Date();
    el.textContent = now.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ---- SSE Connection ----
  let eventSource = null;

  function connectSSE() {
    if (eventSource) { try { eventSource.close(); } catch(_){} }
    eventSource = new EventSource('/api/events');

    eventSource.onopen = function () {
      const dot = document.getElementById('status-dot');
      const txt = document.getElementById('status-text');
      dot.className = 'status-dot connected';
      txt.textContent = t('status.connected');
    };

    eventSource.onerror = function () {
      const dot = document.getElementById('status-dot');
      const txt = document.getElementById('status-text');
      dot.className = 'status-dot disconnected';
      txt.textContent = t('status.disconnected');
    };

    eventSource.addEventListener('access', function (e) {
      try {
        const data = JSON.parse(e.data);
        handleAccessEvent(data);
      } catch (err) { console.error('access parse error', err); }
    });

    eventSource.addEventListener('alert', function (e) {
      try {
        const data = JSON.parse(e.data);
        handleAlertEvent(data);
      } catch (err) { console.error('alert parse error', err); }
    });

    eventSource.addEventListener('stats', function (e) {
      try {
        const data = JSON.parse(e.data);
        handleStatsEvent(data);
      } catch (err) { console.error('stats parse error', err); }
    });
  }

  // ---- Event Handlers ----

  function handleAccessEvent(data) {
    addLogRow(data);
    if (data.geoInfo) {
      updateMapCountry(data.geoInfo);
    }
  }

  function handleAlertEvent(data) {
    addAlert(data);
    showToast(data);
    if (Notification.permission === 'granted') {
      try {
        new Notification(t('alerts.notification') + (data.title || data.type), {
          body: data.detail || data.message || '',
          icon: '/favicon.ico',
        });
      } catch (_) {}
    }
  }

  function handleStatsEvent(data) {
    updateKPI(data);
    if (data.timeline) {
      addTimelinePoint(data.timeline);
    }
    if (data.statusCodes) {
      updateStatusChart(data.statusCodes);
    }
  }

  // ---- KPI Cards ----

  function updateKPI(data) {
    const fields = [
      { key: 'totalRequests', elVal: 'kpi-total-requests', elTrend: 'kpi-total-requests-trend' },
      { key: 'errors4xx',     elVal: 'kpi-4xx',             elTrend: 'kpi-4xx-trend' },
      { key: 'errors5xx',     elVal: 'kpi-5xx',             elTrend: 'kpi-5xx-trend' },
      { key: 'uniqueIps',     elVal: 'kpi-unique-ips',      elTrend: 'kpi-unique-ips-trend' },
    ];

    fields.forEach(function (f) {
      const newVal = data[f.key];
      if (newVal == null) return;
      const el = document.getElementById(f.elVal);
      const trendEl = document.getElementById(f.elTrend);
      const oldVal = state.prevKpi[f.key] || 0;

      animateValue(el, oldVal, newVal, 600);

      if (state.prevKpi[f.key] !== undefined) {
        const diff = newVal - oldVal;
        if (diff > 0) {
          trendEl.textContent = '\u2191 +' + formatNumber(diff);
          trendEl.className = 'kpi-trend trend-up';
        } else if (diff < 0) {
          trendEl.textContent = '\u2193 ' + formatNumber(diff);
          trendEl.className = 'kpi-trend trend-down';
        } else {
          trendEl.textContent = '\u2192 0';
          trendEl.className = 'kpi-trend trend-flat';
        }
      }
      state.prevKpi[f.key] = newVal;
    });
  }

  // ---- Timeline Chart (Chart.js) ----
  let timelineChart = null;

  function initTimelineChart(data) {
    const ctx = document.getElementById('timeline-chart').getContext('2d');
    const points = (data || []).map(function (d) {
      return { x: new Date(d.time || d.t), y: d.count || d.y || 0 };
    });

    timelineChart = new Chart(ctx, {
      type: 'line',
      data: {
        datasets: [{
          label: t('chart.requestsPerMin'),
          data: points,
          borderColor: '#22d3ee',
          backgroundColor: 'rgba(34,211,238,0.08)',
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
          fill: true,
          tension: 0.3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        scales: {
          x: {
            type: 'time',
            time: { unit: 'minute', tooltipFormat: 'HH:mm' },
            grid: { color: 'rgba(30,45,61,0.5)' },
            ticks: { color: '#64748b', maxTicksLimit: 12 },
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(30,45,61,0.5)' },
            ticks: { color: '#64748b' },
          },
        },
        plugins: {
          legend: { display: false },
        },
      },
    });
  }

  function addTimelinePoint(pt) {
    if (!timelineChart) return;
    const ds = timelineChart.data.datasets[0];
    ds.data.push({ x: new Date(pt.time || pt.t), y: pt.count || pt.y || 0 });
    if (ds.data.length > 120) ds.data.shift();
    timelineChart.update('none');
  }

  // ---- Status Code Doughnut (Chart.js) ----
  let statusChart = null;

  function initStatusChart(data) {
    const ctx = document.getElementById('status-chart').getContext('2d');
    const codes = data || { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };

    statusChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['2xx', '3xx', '4xx', '5xx'],
        datasets: [{
          data: [codes['2xx'] || 0, codes['3xx'] || 0, codes['4xx'] || 0, codes['5xx'] || 0],
          backgroundColor: ['#10b981', '#6366f1', '#f59e0b', '#ef4444'],
          borderColor: '#111827',
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#e2e8f0', padding: 12, usePointStyle: true, pointStyleWidth: 10 },
          },
        },
      },
    });
  }

  function updateStatusChart(codes) {
    if (!statusChart) return;
    statusChart.data.datasets[0].data = [
      codes['2xx'] || 0, codes['3xx'] || 0, codes['4xx'] || 0, codes['5xx'] || 0
    ];
    statusChart.update('none');
  }

  // ---- Top 10 IP Bar Chart (Chart.js) ----
  let topIpChart = null;

  function initTopIpChart(data) {
    const ctx = document.getElementById('topip-chart').getContext('2d');
    const items = (data || []).slice(0, 10);
    const labels = items.map(function (d) {
      const flag = d.countryCode ? countryCodeToFlag(d.countryCode) : '';
      return flag + ' ' + d.ip;
    });
    const values = items.map(function (d) { return d.count || 0; });
    const colors = items.map(function (d) { return d.suspicious ? '#ef4444' : '#3b82f6'; });

    topIpChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: t('chart.requests'),
          data: values,
          backgroundColor: colors,
          borderRadius: 4,
          barThickness: 18,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: 'rgba(30,45,61,0.5)' },
            ticks: { color: '#64748b' },
          },
          y: {
            grid: { display: false },
            ticks: { color: '#e2e8f0', font: { family: "'JetBrains Mono', monospace", size: 11 } },
          },
        },
        plugins: {
          legend: { display: false },
        },
      },
    });
  }

  function refreshTopIpChart(data) {
    if (!topIpChart) return;
    const items = (data || []).slice(0, 10);
    topIpChart.data.labels = items.map(function (d) {
      const flag = d.countryCode ? countryCodeToFlag(d.countryCode) : '';
      return flag + ' ' + d.ip;
    });
    topIpChart.data.datasets[0].data = items.map(function (d) { return d.count || 0; });
    topIpChart.data.datasets[0].backgroundColor = items.map(function (d) {
      return d.suspicious ? '#ef4444' : '#3b82f6';
    });
    topIpChart.update('none');
  }

  // ---- World Map (D3.js + TopoJSON) ----
  let mapSvg, mapProjection, mapPath, mapG, arcG, pointG, serverG;
  let mapWidth, mapHeight;

  function initWorldMap() {
    const container = document.getElementById('map-container');
    const rect = container.getBoundingClientRect();
    mapWidth = rect.width || 600;
    mapHeight = rect.height || 340;

    mapSvg = d3.select('#map-container')
      .append('svg')
      .attr('viewBox', '0 0 ' + mapWidth + ' ' + mapHeight)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    // Gradient definition for arcs
    const defs = mapSvg.append('defs');

    const grad = defs.append('linearGradient')
      .attr('id', 'arc-gradient-normal')
      .attr('gradientUnits', 'userSpaceOnUse');
    grad.append('stop').attr('offset', '0%').attr('stop-color', '#22d3ee');
    grad.append('stop').attr('offset', '100%').attr('stop-color', '#22d3ee').attr('stop-opacity', 0.3);

    const gradDanger = defs.append('linearGradient')
      .attr('id', 'arc-gradient-danger')
      .attr('gradientUnits', 'userSpaceOnUse');
    gradDanger.append('stop').attr('offset', '0%').attr('stop-color', '#ef4444');
    gradDanger.append('stop').attr('offset', '100%').attr('stop-color', '#ef4444').attr('stop-opacity', 0.3);

    // Glow filter
    const filter = defs.append('filter').attr('id', 'glow');
    filter.append('feGaussianBlur').attr('stdDeviation', 2).attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    mapProjection = d3.geoNaturalEarth1()
      .scale(mapWidth / 5.5)
      .translate([mapWidth / 2, mapHeight / 2]);

    mapPath = d3.geoPath().projection(mapProjection);

    mapG = mapSvg.append('g').attr('class', 'countries');
    arcG = mapSvg.append('g').attr('class', 'arcs');
    pointG = mapSvg.append('g').attr('class', 'points');
    serverG = mapSvg.append('g').attr('class', 'server');

    // Load world map
    d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then(function (world) {
        const countries = topojson.feature(world, world.objects.countries);

        mapG.selectAll('path')
          .data(countries.features)
          .enter()
          .append('path')
          .attr('d', mapPath)
          .attr('fill', '#1a2332')
          .attr('stroke', '#2a3a4d')
          .attr('stroke-width', 0.5);

        // Server location (Tokyo)
        drawServerMarker();

        // Draw initial country data if loaded
        drawAllArcs();
      })
      .catch(function (err) {
        console.error('Failed to load world map:', err);
      });
  }

  function drawServerMarker() {
    const pos = mapProjection(TOKYO);
    if (!pos) return;

    // Pulse ring
    serverG.append('circle')
      .attr('cx', pos[0])
      .attr('cy', pos[1])
      .attr('r', 3)
      .attr('fill', 'none')
      .attr('stroke', '#22d3ee')
      .attr('stroke-width', 1.5)
      .attr('opacity', 0.8);

    // Animated pulse
    function addPulse() {
      serverG.append('circle')
        .attr('cx', pos[0])
        .attr('cy', pos[1])
        .attr('r', 3)
        .attr('fill', 'none')
        .attr('stroke', '#22d3ee')
        .attr('stroke-width', 1)
        .attr('opacity', 0.8)
        .transition()
        .duration(2000)
        .ease(d3.easeQuadOut)
        .attr('r', 18)
        .attr('opacity', 0)
        .remove();
    }

    addPulse();
    setInterval(addPulse, 2000);

    // Center dot
    serverG.append('circle')
      .attr('cx', pos[0])
      .attr('cy', pos[1])
      .attr('r', 3)
      .attr('fill', '#22d3ee')
      .style('filter', 'url(#glow)');
  }

  function drawAllArcs() {
    if (!arcG || !pointG) return;

    const tooltip = document.getElementById('map-tooltip');

    // Clear existing
    arcG.selectAll('*').remove();
    pointG.selectAll('*').remove();

    const maxCount = Math.max(1, ...Array.from(state.countries.values()).map(function (c) { return c.count; }));

    state.countries.forEach(function (info, code) {
      const target = [info.lng, info.lat];
      const proj = mapProjection(target);
      if (!proj) return;
      const serverProj = mapProjection(TOKYO);
      if (!serverProj) return;

      const ratio = info.count / maxCount;
      const thickness = 1 + ratio * 3;
      const opacity = 0.3 + ratio * 0.7;
      const isSuspicious = info.suspicious || false;
      const color = isSuspicious ? '#ef4444' : '#22d3ee';

      // Great circle arc
      const lineGen = d3.geoPath().projection(mapProjection);
      const arcData = {
        type: 'LineString',
        coordinates: [TOKYO, target],
      };

      const arcPath = arcG.append('path')
        .datum(arcData)
        .attr('d', lineGen)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', thickness)
        .attr('stroke-opacity', opacity)
        .attr('stroke-linecap', 'round')
        .style('filter', 'url(#glow)');

      // Animate stroke-dasharray
      const pathNode = arcPath.node();
      if (pathNode) {
        const totalLength = pathNode.getTotalLength();
        arcPath
          .attr('stroke-dasharray', totalLength)
          .attr('stroke-dashoffset', totalLength)
          .transition()
          .duration(1500)
          .ease(d3.easeCubicOut)
          .attr('stroke-dashoffset', 0);
      }

      // Destination dot
      const dotRadius = Math.max(2, Math.min(6, 2 + ratio * 4));
      const dot = pointG.append('circle')
        .attr('cx', proj[0])
        .attr('cy', proj[1])
        .attr('r', dotRadius)
        .attr('fill', color)
        .attr('fill-opacity', 0.8)
        .style('filter', 'url(#glow)')
        .style('cursor', 'pointer');

      // Tooltip
      dot.on('mouseenter', function (event) {
        const flag = countryCodeToFlag(code);
        tooltip.innerHTML =
          '<div class="tt-country">' + flag + ' ' + (info.name || code) + '</div>' +
          '<div class="tt-count">' + formatNumber(info.count) + ' ' + t('tooltip.requests') + '</div>';
        tooltip.classList.add('visible');
      });

      dot.on('mousemove', function (event) {
        const containerRect = document.getElementById('map-container').getBoundingClientRect();
        tooltip.style.left = (event.clientX - containerRect.left + 12) + 'px';
        tooltip.style.top = (event.clientY - containerRect.top - 10) + 'px';
      });

      dot.on('mouseleave', function () {
        tooltip.classList.remove('visible');
      });
    });
  }

  function updateMapCountry(geoInfo) {
    if (!geoInfo || !geoInfo.countryCode) return;
    const code = geoInfo.countryCode;
    const existing = state.countries.get(code);
    if (existing) {
      existing.count += 1;
      if (geoInfo.suspicious) existing.suspicious = true;
    } else {
      state.countries.set(code, {
        name: geoInfo.country || code,
        lat: geoInfo.lat || 0,
        lng: geoInfo.lng || 0,
        count: 1,
        suspicious: geoInfo.suspicious || false,
      });
    }
    pulseArc(code);
  }

  function pulseArc(code) {
    if (!arcG || !mapProjection) return;
    const info = state.countries.get(code);
    if (!info) return;
    const target = [info.lng, info.lat];
    const proj = mapProjection(target);
    if (!proj) return;

    const isSuspicious = info.suspicious || false;
    const color = isSuspicious ? '#ef4444' : '#22d3ee';

    const arcData = {
      type: 'LineString',
      coordinates: [TOKYO, target],
    };
    const lineGen = d3.geoPath().projection(mapProjection);

    const flash = arcG.append('path')
      .datum(arcData)
      .attr('d', lineGen)
      .attr('fill', 'none')
      .attr('stroke', color)
      .attr('stroke-width', 3)
      .attr('stroke-opacity', 1)
      .style('filter', 'url(#glow)');

    const node = flash.node();
    if (node) {
      const len = node.getTotalLength();
      flash
        .attr('stroke-dasharray', len)
        .attr('stroke-dashoffset', len)
        .transition()
        .duration(800)
        .ease(d3.easeCubicOut)
        .attr('stroke-dashoffset', 0)
        .transition()
        .duration(600)
        .attr('stroke-opacity', 0)
        .remove();
    }

    // Redraw all arcs periodically (throttled)
    if (!pulseArc._timer) {
      pulseArc._timer = setTimeout(function () {
        drawAllArcs();
        pulseArc._timer = null;
      }, 2000);
    }
  }

  // ---- Alerts Panel ----

  function addAlert(data) {
    state.alerts.unshift(data);
    if (state.alerts.length > MAX_ALERTS) state.alerts.pop();

    const list = document.getElementById('alerts-list');
    const card = createAlertCard(data);
    list.insertBefore(card, list.firstChild);

    // Trim DOM
    while (list.children.length > MAX_ALERTS) {
      list.removeChild(list.lastChild);
    }

    document.getElementById('alert-count').textContent = state.alerts.length;
  }

  function createAlertCard(data) {
    const severity = (data.severity || 'low').toLowerCase();
    const ruleId = data.type || data.ruleId || '';
    const card = document.createElement('div');
    card.className = 'alert-card severity-' + severity;

    const time = document.createElement('div');
    time.className = 'alert-time';
    time.textContent = shortTime(data.timestamp || new Date().toISOString());

    const body = document.createElement('div');
    body.className = 'alert-body';

    // Title: use i18n rule name if available, fallback to original
    const ruleName = t('rule.' + ruleId);
    const title = document.createElement('div');
    title.className = 'alert-title';
    title.textContent = (ruleName !== 'rule.' + ruleId) ? ruleName : (data.title || data.type || 'Alert');

    // Technical detail (IP, path, etc.)
    const detail = document.createElement('div');
    detail.className = 'alert-detail';
    detail.textContent = data.detail || data.message || '';

    body.appendChild(title);
    body.appendChild(detail);

    // Rule description (what this threat means)
    const ruleDesc = t('rule.' + ruleId + '.desc');
    if (ruleDesc !== 'rule.' + ruleId + '.desc') {
      const descDiv = document.createElement('div');
      descDiv.className = 'alert-rule-desc';
      descDiv.textContent = ruleDesc;
      body.appendChild(descDiv);
    }

    // Recommended action
    const ruleAction = t('rule.' + ruleId + '.action');
    if (ruleAction !== 'rule.' + ruleId + '.action') {
      const actionDiv = document.createElement('div');
      actionDiv.className = 'alert-rule-action';
      actionDiv.textContent = ruleAction;
      body.appendChild(actionDiv);
    }

    // Severity badge with translated label
    const severityLabel = t('severity.' + severity);
    const badge = document.createElement('div');
    badge.className = 'alert-severity-badge ' + severity;
    badge.textContent = (severityLabel !== 'severity.' + severity) ? severityLabel : severity;
    badge.title = t('severity.' + severity + '.desc');

    card.appendChild(time);
    card.appendChild(body);
    card.appendChild(badge);

    return card;
  }

  function renderAlerts(alertsData) {
    const list = document.getElementById('alerts-list');
    list.innerHTML = '';
    (alertsData || []).forEach(function (a) {
      state.alerts.push(a);
      list.appendChild(createAlertCard(a));
    });
    document.getElementById('alert-count').textContent = state.alerts.length;
  }

  // ---- Toast Notifications ----

  function showToast(data) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';

    const severity = (data.severity || 'low').toLowerCase();
    const borderColor = severity === 'critical' ? '#dc2626'
      : severity === 'high' ? '#ef4444'
      : severity === 'medium' ? '#f59e0b'
      : '#64748b';
    toast.style.borderLeftColor = borderColor;

    toast.innerHTML =
      '<div class="toast-title">[' + severity.toUpperCase() + '] ' + (data.title || data.type || 'Alert') + '</div>' +
      '<div class="toast-body">' + (data.detail || data.message || '') + '</div>';

    container.appendChild(toast);

    setTimeout(function () {
      toast.classList.add('toast-out');
      setTimeout(function () { toast.remove(); }, 300);
    }, TOAST_DURATION);
  }

  // ---- Log Stream ----

  function addLogRow(data) {
    state.logs.unshift(data);
    if (state.logs.length > MAX_LOG_ROWS) state.logs.pop();

    const tbody = document.getElementById('log-tbody');
    const row = createLogRow(data);

    // Apply filter
    if (!matchesFilter(data)) {
      row.classList.add('filtered-out');
    }

    tbody.insertBefore(row, tbody.firstChild);

    // Trim DOM
    while (tbody.children.length > MAX_LOG_ROWS) {
      tbody.removeChild(tbody.lastChild);
    }

    // Auto-scroll
    if (state.autoScroll) {
      const wrapper = document.getElementById('log-table-wrapper');
      wrapper.scrollTop = 0;
    }
  }

  function createLogRow(data) {
    const tr = document.createElement('tr');
    tr.className = 'log-new';
    tr.dataset.service = (data.service || '').toLowerCase();
    tr.dataset.status = String(data.status || 0);
    tr.dataset.ip = data.ip || '';
    tr.dataset.path = data.path || '';

    const sc = statusClass(data.status);
    const svcCls = serviceClass(data.service);
    const flag = data.geoInfo ? countryCodeToFlag(data.geoInfo.countryCode) : '';

    tr.innerHTML =
      '<td>' + shortTime(data.timestamp || new Date().toISOString()) + '</td>' +
      '<td><span class="status-badge ' + sc + '">' + (data.status || '-') + '</span></td>' +
      '<td>' + (data.method || '-') + '</td>' +
      '<td title="' + escapeHtml(data.path || '') + '">' + truncate(data.path || '-', 40) + '</td>' +
      '<td>' + (data.ip || '-') + '</td>' +
      '<td>' + flag + '</td>' +
      '<td><span class="svc-badge ' + svcCls + '">' + (data.service || '-') + '</span></td>';

    // Remove animation class after it plays
    setTimeout(function () { tr.classList.remove('log-new'); }, 600);

    return tr;
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
  }

  function matchesFilter(data) {
    const f = state.filters;
    if (f.service && !(data.service || '').toLowerCase().includes(f.service.toLowerCase())) return false;
    if (f.status) {
      const s = String(data.status || 0);
      if (f.status === '2xx' && (s[0] !== '2')) return false;
      if (f.status === '3xx' && (s[0] !== '3')) return false;
      if (f.status === '4xx' && (s[0] !== '4')) return false;
      if (f.status === '5xx' && (s[0] !== '5')) return false;
    }
    if (f.ip && !(data.ip || '').includes(f.ip)) return false;
    if (f.path && !(data.path || '').toLowerCase().includes(f.path.toLowerCase())) return false;
    return true;
  }

  function applyFilters() {
    const tbody = document.getElementById('log-tbody');
    const rows = tbody.querySelectorAll('tr');
    rows.forEach(function (row) {
      const data = {
        service: row.dataset.service,
        status: row.dataset.status,
        ip: row.dataset.ip,
        path: row.dataset.path,
      };
      if (matchesFilter(data)) {
        row.classList.remove('filtered-out');
      } else {
        row.classList.add('filtered-out');
      }
    });
  }

  // ---- Filter Bar Setup ----

  function setupFilters() {
    document.getElementById('filter-service').addEventListener('change', function (e) {
      state.filters.service = e.target.value;
      applyFilters();
    });

    document.getElementById('filter-status').addEventListener('change', function (e) {
      state.filters.status = e.target.value;
      applyFilters();
    });

    document.getElementById('filter-ip').addEventListener('input', function (e) {
      state.filters.ip = e.target.value;
      applyFilters();
    });

    document.getElementById('filter-path').addEventListener('input', function (e) {
      state.filters.path = e.target.value;
      applyFilters();
    });

    document.getElementById('filter-clear').addEventListener('click', function () {
      state.filters = { service: '', status: '', ip: '', path: '' };
      document.getElementById('filter-service').value = '';
      document.getElementById('filter-status').value = '';
      document.getElementById('filter-ip').value = '';
      document.getElementById('filter-path').value = '';
      applyFilters();
    });

    document.getElementById('autoscroll-toggle').addEventListener('change', function (e) {
      state.autoScroll = e.target.checked;
    });
  }

  // ---- Initial Data Load ----

  function loadServiceConfig() {
    return fetch('/api/config/services')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (cfg) {
        if (!cfg || !cfg.services) return;
        var select = document.getElementById('filter-service');
        cfg.services.forEach(function (svc) {
          serviceColors[svc.name.toLowerCase()] = svc.color || '#64748b';
          var opt = document.createElement('option');
          opt.value = svc.name;
          opt.textContent = svc.name;
          select.appendChild(opt);
        });
        // Inject dynamic CSS for service badges
        var style = document.createElement('style');
        var css = '';
        cfg.services.forEach(function (svc) {
          var cls = svc.name.toLowerCase().replace(/[^a-z0-9]/g, '-');
          css += '.svc-badge.' + cls + ' { background: ' + (svc.color || '#64748b') + '22; color: ' + (svc.color || '#64748b') + '; }\n';
        });
        style.textContent = css;
        document.head.appendChild(style);
      })
      .catch(function () {});
  }

  function loadInitialData() {
    const fetches = [
      fetch('/api/summary').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('/api/timeline?range=1h').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('/api/top/ips').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('/api/alerts').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('/api/countries').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
    ];

    Promise.all(fetches).then(function (results) {
      var summary = results[0];
      var timeline = results[1];
      var topIps = results[2];
      var alerts = results[3];
      var countries = results[4];

      // KPI from summary
      if (summary) {
        updateKPI(summary);
      }

      // Timeline chart
      initTimelineChart(timeline);

      // Status chart from summary
      initStatusChart(summary ? summary.statusCodes : null);

      // Top IPs
      initTopIpChart(topIps);

      // Alerts
      if (alerts) {
        renderAlerts(alerts);
      }

      // Countries for map
      if (countries && Array.isArray(countries)) {
        countries.forEach(function (c) {
          state.countries.set(c.countryCode || c.code, {
            name: c.country || c.name || c.countryCode,
            lat: c.lat || 0,
            lng: c.lng || 0,
            count: c.count || 0,
            suspicious: c.suspicious || false,
          });
        });
        drawAllArcs();
      }
    });
  }

  // ---- Request Notification Permission ----

  function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }

  // ---- Map resize handler ----

  function handleResize() {
    if (!mapSvg) return;
    const container = document.getElementById('map-container');
    const rect = container.getBoundingClientRect();
    mapWidth = rect.width || 600;
    mapHeight = rect.height || 340;
    mapSvg.attr('viewBox', '0 0 ' + mapWidth + ' ' + mapHeight);
    mapProjection
      .scale(mapWidth / 5.5)
      .translate([mapWidth / 2, mapHeight / 2]);
    // Re-render countries and arcs
    mapG.selectAll('path').attr('d', mapPath);
    serverG.selectAll('*').remove();
    drawServerMarker();
    drawAllArcs();
  }

  let resizeTimer;
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(handleResize, 300);
  });

  // ---- Language Selector ----

  function setupLangSelector() {
    var select = document.getElementById('lang-select');
    if (!select || !window.i18n) return;

    var langs = window.i18n.getAvailableLangs();
    var current = window.i18n.getLang();

    select.innerHTML = '';
    Object.keys(langs).forEach(function (code) {
      var opt = document.createElement('option');
      opt.value = code;
      opt.textContent = langs[code];
      if (code === current) opt.selected = true;
      select.appendChild(opt);
    });

    select.addEventListener('change', function (e) {
      window.i18n.setLang(e.target.value);
    });

    // Listen for langchange event to update dynamic elements
    window.addEventListener('langchange', function () {
      // Update chart labels if charts exist
      if (timelineChart) {
        timelineChart.data.datasets[0].label = t('chart.requestsPerMin');
        timelineChart.update('none');
      }
      if (topIpChart) {
        topIpChart.data.datasets[0].label = t('chart.requests');
        topIpChart.update('none');
      }
    });
  }

  // ---- Initialize ----

  function init() {
    setupLangSelector();
    if (window.i18n) window.i18n.applyTranslations();
    setupFilters();
    initWorldMap();
    loadServiceConfig().then(function () {
      loadInitialData();
    });
    connectSSE();
    requestNotificationPermission();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
