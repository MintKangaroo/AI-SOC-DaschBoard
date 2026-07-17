/* ══════════════════════════════════════════
   SOC Dashboard — Main JS
══════════════════════════════════════════ */

/* 세션 만료 감지: /api 응답이 401이면 로그인 페이지로 이동 */
(function () {
  const _fetch = window.fetch;
  window.fetch = function (...args) {
    return _fetch.apply(this, args).then(res => {
      if (res.status === 401 && String(args[0] || '').includes('/api/')) {
        window.location.href = '/login';
      }
      return res;
    });
  };
})();

const socket = io();
// 소켓 인증 실패(미로그인) 시 로그인 페이지로
socket.on('connect_error', () => { window.location.href = '/login'; });

/* ─────────────────── 유틸 ─────────────────── */
function fmtBytes(b) {
  if (b < 1024)       return b + ' B';
  if (b < 1048576)    return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}

function sevBadge(sev) {
  return `<span class="badge sev-${sev}">${sev}</span>`;
}

function protoColor(p) {
  const m = { TCP:'#39d0d8', UDP:'#9d79f2', ICMP:'#e3b341', ARP:'#3fb950', OTHER:'#8b949e' };
  return m[p] || '#8b949e';
}

function threatColor(t) {
  const m = { DDOS:'#f85149', PORT_SCAN:'#f79000', BRUTE_FORCE:'#e3b341',
               MALWARE_BEACON:'#f85149', DATA_EXFIL:'#f79000',
               ARP_SPOOFING:'#9d79f2', DNS_TUNNELING:'#58a6ff', ANOMALY:'#8b949e' };
  return m[t] || '#8b949e';
}

/* ─────────────────── 모바일 사이드바 드로어 ─────────────────── */
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const bd = document.getElementById('sidebar-backdrop');
  const open = sb.classList.toggle('open');
  if (bd) bd.classList.toggle('show', open);
}
function closeSidebar() {
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebar-backdrop')?.classList.remove('show');
}

/* ─────────────────── 패널 전환 ─────────────────── */
function showPanel(name) {
  document.querySelectorAll('.panel-section').forEach(p => p.classList.add('d-none'));
  const target = document.getElementById('panel-' + name);
  if (target) target.classList.remove('d-none');

  document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
  const link = document.querySelector(`[data-panel="${name}"]`);
  if (link) link.classList.add('active');

  closeSidebar();   // 모바일: 패널 선택 시 드로어 닫기

  if (name === 'overview') setTimeout(initMap, 50);
  if (name === 'traffic') initTrafficCharts();
  if (name === 'alerts') loadAlerts();
  if (name === 'packets') initPacketsTable();
  if (name === 'sysmon') initSysmonTable();
  if (name === 'ml') { setTimeout(initMLCharts, 50); loadDecisionSupport(); }
  if (name === 'mitre') loadMitreMatrix();
  if (name === 'threat-intel') loadThreatIntel();
  if (name === 'siem') loadSiem();
  if (name === 'authlog') loadAuthlog();
  if (name === 'reputation') loadReputation();
  if (name === 'edr') loadEdr();
  if (name === 'network') loadNetwork();
  if (name === 'sigma') loadSigma();
  if (name === 'vulnscan') loadVulnScan();
  if (name === 'fuzz') loadFuzz();
  if (name === 'patch') loadPatch();
  if (name === 'notify') loadNotify();
  if (name === 'report') loadReport();
  if (name === 'purple') loadPurple();
  if (name === 'soar') loadSoar();
  if (name === 'incidents') loadIncidents();
  if (name === 'myinfo') loadMyInfo();
}

/* ════════════════════ 내 정보 (System Info) ════════════════════ */
async function loadMyInfo(force) {
  try {
    const res  = await fetch('/api/system/info' + (force ? '?t=' + Date.now() : ''));
    const data = await res.json();
    renderMyInfo(data);
  } catch (e) {
    console.error('[myinfo] load failed', e);
  }
}

function renderMyInfo(d) {
  const host = d.host || {}, net = d.network || {}, res = d.resources || {};
  const geo  = net.geo || {};

  document.getElementById('myinfo-last-update').textContent = '최종 조회 ' + (d.timestamp || '');

  // 공인 IP
  document.getElementById('myinfo-public-ip').textContent = net.public_ip || '조회 실패';
  if (geo && geo.country) {
    document.getElementById('myinfo-geo').innerHTML =
      `<i class="fa fa-location-dot me-1"></i>${escapeHtml(geo.country)} · ${escapeHtml(geo.city || geo.regionName || '')}`;
    document.getElementById('myinfo-isp').textContent = geo.isp || geo.org || 'ISP —';
  } else {
    document.getElementById('myinfo-geo').innerHTML = '<i class="fa fa-location-dot me-1"></i>' + (net.public_ip ? '위치 정보 없음' : '외부 접근 불가');
    document.getElementById('myinfo-isp').textContent = 'ISP —';
  }

  // 사설 IP
  document.getElementById('myinfo-private-ip').textContent = net.primary_private_ip || '—';
  const extra = (net.private_ips || []).slice(1);
  document.getElementById('myinfo-private-ip-all').textContent =
    extra.length ? '보조 ' + extra.join(', ') : '단일 IP';

  // 호스트
  document.getElementById('myinfo-hostname').textContent = host.hostname || '—';
  document.getElementById('myinfo-username').textContent = host.username ? '@' + host.username : '—';
  document.getElementById('myinfo-mac').textContent = host.mac || '—';

  // 시스템 grid (key-value 리스트)
  const osLine = `${host.os || ''} ${host.os_release || ''}`.trim();
  const sysRows = [
    ['fa-server',       '호스트명',    host.hostname || '—'],
    ['fa-globe',        'FQDN',         host.fqdn || '—'],
    ['fa-brands fa-windows', 'OS',     osLine || '—'],
    ['fa-tag',          'OS 버전',     host.os_version || '—'],
    ['fa-layer-group',  '플랫폼',      host.platform || '—'],
    ['fa-microchip',    '아키텍처',    host.architecture || '—'],
    ['fa-microchip',    'CPU',         host.processor || '—'],
    ['fa-brands fa-python', 'Python', host.python_version || '—'],
    ['fa-ethernet',     'MAC',         host.mac || '—'],
  ];
  document.getElementById('myinfo-system-grid').innerHTML = sysRows.map(([ic, k, v]) => `
    <div class="kv-row">
      <div class="kv-key"><i class="fa ${ic}"></i>${k}</div>
      <div class="kv-val font-monospace">${escapeHtml(v)}</div>
    </div>`).join('');

  // 리소스 (진행률 바)
  const uptime = res.uptime_sec ? formatUptime(res.uptime_sec) : '—';
  const bars = [
    barHtml('fa-gauge-high',  'CPU',     res.cpu_percent,
            res.cpu_percent != null ? res.cpu_percent + ' %' : '—',
            res.cpu_count ? res.cpu_count + ' core' : ''),
    barHtml('fa-memory',      '메모리',  res.mem_percent,
            (res.mem_used_mb != null)
              ? `${fmtMB(res.mem_used_mb)} / ${fmtMB(res.mem_total_mb)}` : '—',
            res.mem_percent != null ? res.mem_percent + ' %' : ''),
    barHtml('fa-hard-drive',  '디스크',  res.disk_percent,
            (res.disk_used_gb != null)
              ? `${res.disk_used_gb} / ${res.disk_total_gb} GB` : '—',
            res.disk_percent != null ? res.disk_percent + ' %' : ''),
  ].join('');
  const meta = `
    <div class="kv-row"><div class="kv-key"><i class="fa fa-power-off"></i>부팅 시각</div>
      <div class="kv-val font-monospace">${escapeHtml(res.boot_time || '—')}</div></div>
    <div class="kv-row"><div class="kv-key"><i class="fa fa-clock"></i>가동 시간</div>
      <div class="kv-val font-monospace">${escapeHtml(uptime)}</div></div>`;
  document.getElementById('myinfo-resource-box').innerHTML =
    `<div class="resource-bars">${bars}</div><div class="kv-grid mt-2">${meta}</div>`;

  // 인터페이스
  const ifaces = net.interfaces || [];
  const box = document.getElementById('myinfo-iface-list');
  if (!ifaces.length) {
    box.innerHTML = '<div class="kv-placeholder">인터페이스 정보 없음</div>';
  } else {
    box.innerHTML = `<div class="iface-grid">${ifaces.map(ifaceCard).join('')}</div>`;
  }
}

function barHtml(icon, label, percent, valText, rightText) {
  const pct = Math.max(0, Math.min(100, Number(percent) || 0));
  let cls = 'bar-low';
  if (pct >= 85) cls = 'bar-high';
  else if (pct >= 60) cls = 'bar-mid';
  return `
    <div class="res-item">
      <div class="res-head">
        <span><i class="fa ${icon} me-2 text-cyan"></i>${label}</span>
        <span class="font-monospace">${escapeHtml(valText)}</span>
      </div>
      <div class="res-bar"><div class="res-fill ${cls}" style="width:${pct}%"></div></div>
      <div class="res-foot">${escapeHtml(rightText || '')}</div>
    </div>`;
}

function ifaceCard(i) {
  const isUp = !!i.is_up;
  return `
    <div class="iface-card ${isUp ? 'up' : 'down'}">
      <div class="iface-head">
        <span class="iface-dot"></span>
        <span class="iface-name" title="${escapeHtml(i.name || '')}">${escapeHtml(i.name || '—')}</span>
        <span class="iface-status">${isUp ? 'UP' : 'DOWN'}</span>
      </div>
      <div class="iface-row"><span class="iface-k">IPv4</span><span class="iface-v font-monospace">${escapeHtml(i.ipv4 || '—')}</span></div>
      <div class="iface-row"><span class="iface-k">IPv6</span><span class="iface-v font-monospace" title="${escapeHtml(i.ipv6||'')}">${escapeHtml(i.ipv6 || '—')}</span></div>
      <div class="iface-row"><span class="iface-k">MAC</span><span class="iface-v font-monospace">${escapeHtml(i.mac || '—')}</span></div>
      <div class="iface-row"><span class="iface-k">속도</span><span class="iface-v">${i.speed_mbps ? i.speed_mbps + ' Mbps' : '—'}</span></div>
    </div>`;
}

function fmtMB(mb) {
  if (mb == null) return '—';
  return mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : mb + ' MB';
}

function formatUptime(sec) {
  sec = Number(sec) || 0;
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return (d ? d + '일 ' : '') + (h ? h + '시간 ' : '') + m + '분';
}

document.querySelectorAll('.sidebar-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    showPanel(link.dataset.panel);
  });
});

/* ─────────────────── 시간 표시 ─────────────────── */
setInterval(() => {
  document.getElementById('current-time').textContent =
    new Date().toLocaleString('ko-KR', { hour12: false });
}, 1000);

/* ════════════════════ OVERVIEW 차트 ════════════════════ */
const miniTrafficCtx = document.getElementById('mini-traffic-chart').getContext('2d');
const miniTrafficChart = new Chart(miniTrafficCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'pps',
      data: [],
      borderColor: '#39d0d8',
      backgroundColor: 'rgba(57,208,216,.1)',
      tension: 0.4, fill: true, pointRadius: 0, borderWidth: 2,
    }],
  },
  options: {
    animation: false, responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8b949e', maxTicksLimit: 8, font:{size:10} }, grid: { color: '#21262d' } },
      y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
    },
  },
});

const protoCtx = document.getElementById('proto-chart').getContext('2d');
const protoChart = new Chart(protoCtx, {
  type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
  options: {
    animation: false, responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font:{size:10}, padding:6 } } },
  },
});

const sevCtx = document.getElementById('severity-chart').getContext('2d');
const sevChart = new Chart(sevCtx, {
  type: 'doughnut',
  data: {
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    datasets: [{ data: [0, 0, 0, 0], backgroundColor: ['#f85149','#f79000','#e3b341','#58a6ff'] }],
  },
  options: {
    animation: false, responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font:{size:10}, padding:6 } } },
  },
});

/* ─────────── Socket: 패킷 업데이트 ─────────── */
socket.on('packet_update', data => {
  const s = data.stats;
  document.getElementById('stat-pps').textContent = s.packets_per_sec.toLocaleString();
  document.getElementById('stat-total-packets').textContent = s.total_packets.toLocaleString();

  // 미니 차트 갱신
  const hist = data.traffic_history || [];
  miniTrafficChart.data.labels = hist.map(h => h.time);
  miniTrafficChart.data.datasets[0].data = hist.map(h => h.pps);
  miniTrafficChart.update('none');

  // 프로토콜 차트
  const pd = data.protocol_dist || {};
  protoChart.data.labels = Object.keys(pd);
  protoChart.data.datasets[0].data = Object.values(pd);
  protoChart.data.datasets[0].backgroundColor = Object.keys(pd).map(protoColor);
  protoChart.update('none');

  // 패킷 테이블 (패킷 패널)
  updatePacketsTable(data.recent_packets || []);

  // 트래픽 패널 차트
  updateTrafficCharts(data);
});

/* ─────────── Socket: 위협 알림 ─────────── */
const _attackerCounter = {};
const _threatTypeCounter = {};
let _threatTypeChart = null;

socket.on('new_alert', alert => {
  prependAlertRow(alert);
  prependOverviewAlert(alert);
  updateSeverityChart(alert.severity);

  document.getElementById('stat-total-alerts').textContent =
    parseInt(document.getElementById('stat-total-alerts').textContent || 0) + 1;
  adjustOpenAlerts(+1);

  // KPI: CRITICAL / HIGH
  if (alert.severity === 'CRITICAL') incEl('kpi-critical');
  if (alert.severity === 'HIGH')     incEl('kpi-high');

  // TOP 공격자
  _attackerCounter[alert.src_ip] = _attackerCounter[alert.src_ip] || { count: 0, type: alert.threat_type };
  _attackerCounter[alert.src_ip].count++;
  _attackerCounter[alert.src_ip].type = alert.threat_type;
  document.getElementById('kpi-unique-attackers').textContent = Object.keys(_attackerCounter).length;
  renderTopAttackers();

  // 위협 유형 차트
  _threatTypeCounter[alert.threat_label] = (_threatTypeCounter[alert.threat_label] || 0) + 1;
  renderThreatTypeChart();

  // THREAT LEVEL 재계산
  updateThreatLevel();

  // 통합 라이브 스트림
  const conf = alert.confidence != null ? ` · 신뢰도 ${Math.round(alert.confidence*100)}%` : '';
  pushLive('alert', alert.severity,
    `<b style="color:${threatColor(alert.threat_type)}">${escapeHtml(alert.threat_label)}</b> ` +
    `<span class="lv-ip">${escapeHtml(alert.src_ip)}</span> → ${escapeHtml(alert.dst_ip)}${conf}` +
    demoBadge(alert.details),
    { lowConf: !!alert.details?.low_confidence });

  // AI 자동 분석 (CRITICAL/HIGH)
  if (['CRITICAL', 'HIGH'].includes(alert.severity)) {
    socket.emit('request_ai_analysis', { alert });
  }
});

function incEl(id) {
  const el = document.getElementById(id);
  if (el) el.textContent = parseInt(el.textContent || 0) + 1;
}

/* ════════════════════ 통합 라이브 이벤트 스트림 (AI 관제 센터) ════════════════════ */
let _liveFilter = 'all';
let _tpOnly = false;         // 정탐만 보기 (오탐 의심=저신뢰 알림 숨김)
const _liveBuffer = [];
const LIVE_MAX = 120;

const LIVE_KIND_META = {
  alert:    { cls: 'k-alert',    label: '알림' },
  siem:     { cls: 'k-siem',     label: 'SIEM' },
  auth:     { cls: 'k-auth',     label: 'SSH' },
  soar:     { cls: 'k-soar',     label: '대응' },
  incident: { cls: 'k-incident', label: '인시던트' },
  ti:       { cls: 'k-ti',       label: 'IoC' },
  rep:      { cls: 'k-rep',      label: '평판' },
  edr:      { cls: 'k-edr',      label: 'EDR' },
  net:      { cls: 'k-net',      label: '네트워크' },
  sigma:    { cls: 'k-sigma',    label: 'Sigma' },
};

function pushLive(kind, severity, html, meta) {
  const now = new Date().toTimeString().slice(0, 8);
  _liveBuffer.unshift({
    kind, severity: (severity || 'info').toLowerCase(), html, time: now,
    lowConf: !!(meta && meta.lowConf),   // 오탐 의심 알림 표시
  });
  while (_liveBuffer.length > LIVE_MAX) _liveBuffer.pop();
  renderLiveStream();
}

function renderLiveStream() {
  const box = document.getElementById('live-stream');
  if (!box) return;
  const items = _liveBuffer.filter(e =>
    (_liveFilter === 'all' || e.kind === _liveFilter) &&
    (!_tpOnly || !e.lowConf));
  if (!items.length) {
    box.innerHTML = '<div class="text-muted p-3 small text-center">이벤트 수신 대기 중…</div>';
    return;
  }
  box.innerHTML = items.slice(0, 60).map(e => {
    const meta = LIVE_KIND_META[e.kind] || { cls: '', label: e.kind };
    return `<div class="live-item">
      <div class="lv-bar b-${e.severity}"></div>
      <div class="lv-time">${escapeHtml(e.time)}</div>
      <div class="lv-kind ${meta.cls}">${meta.label}</div>
      <div class="lv-text">${e.html}</div>
    </div>`;
  }).join('');
}

function setLiveFilter(f, btn) {
  _liveFilter = f;
  document.querySelectorAll('.live-filter').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderLiveStream();
}

/* 정탐만 보기 토글 — 라이브 스트림 + 알림 테이블 동시 적용.
   el 이 체크박스면 checked, 버튼이면 클래스 토글로 상태 결정 후 양쪽 UI 동기화. */
function toggleTpOnly(el) {
  if (el && el.type === 'checkbox') {
    _tpOnly = el.checked;
  } else {
    _tpOnly = !_tpOnly;
  }
  // 라이브 스트림 헤더 버튼 상태
  const liveBtn = document.querySelector('.tp-toggle');
  if (liveBtn) liveBtn.classList.toggle('active', _tpOnly);
  // 알림 패널 체크박스 상태
  const chk = document.getElementById('alert-tp-only');
  if (chk) chk.checked = _tpOnly;

  renderLiveStream();
  if (alertsDataTable) alertsDataTable.draw();
}

/* 알림 테이블 '정탐만' 필터 — 오탐 의심(data-lowconf=1) 행 숨김 */
if (window.jQuery && $.fn.dataTable) {
  $.fn.dataTable.ext.search.push((settings, data, dataIndex) => {
    if (settings.nTable.id !== 'alerts-table' || !_tpOnly) return true;
    const tr = settings.aoData[dataIndex].nTr;
    return !tr || tr.dataset.lowconf !== '1';
  });
}

// 파이프라인 상태 갱신
function setPipe(id, v) {
  const el = document.getElementById(id);
  if (el && v != null) el.textContent = Number(v).toLocaleString();
}

/* 미처리 알림 수를 증감하며 사이드바 배지와 동기화 */
function adjustOpenAlerts(delta) {
  const openEl = document.getElementById('stat-open-alerts');
  const sideEl = document.getElementById('sidebar-alert-count');
  const next = Math.max(0, parseInt(openEl?.textContent || 0) + delta);
  if (openEl) openEl.textContent = next;
  if (sideEl) sideEl.textContent = next;
}
function setOpenAlerts(n) {
  const openEl = document.getElementById('stat-open-alerts');
  const sideEl = document.getElementById('sidebar-alert-count');
  if (openEl) openEl.textContent = n;
  if (sideEl) sideEl.textContent = n;
}

function renderTopAttackers() {
  const el = document.getElementById('top-attackers-list');
  if (!el) return;
  const sorted = Object.entries(_attackerCounter)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 8);
  if (!sorted.length) {
    el.innerHTML = '<div class="text-muted p-2">데이터 없음</div>';
    return;
  }
  el.innerHTML = sorted.map(([ip, info], i) => `
    <div class="top-attacker-row">
      <span class="rnk">#${i+1}</span>
      <span class="ip">${ip}</span>
      <span class="ttype">${info.type}</span>
      <span class="cnt">${info.count}</span>
    </div>`).join('');
}

function renderThreatTypeChart() {
  const ctx = document.getElementById('threat-type-chart')?.getContext('2d');
  if (!ctx) return;
  const labels = Object.keys(_threatTypeCounter);
  const data   = Object.values(_threatTypeCounter);
  if (!_threatTypeChart) {
    _threatTypeChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ data, backgroundColor: '#f8514944', borderColor: '#f85149', borderWidth: 1 }] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color:'#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color:'#21262d' } },
        },
      },
    });
  } else {
    _threatTypeChart.data.labels = labels;
    _threatTypeChart.data.datasets[0].data = data;
    _threatTypeChart.update('none');
  }
}

function updateThreatLevel() {
  const crit = parseInt(document.getElementById('kpi-critical').textContent || 0);
  const high = parseInt(document.getElementById('kpi-high').textContent || 0);
  const open = parseInt(document.getElementById('stat-open-alerts').textContent || 0);
  const badge = document.getElementById('threat-level-badge');
  if (!badge) return;
  badge.classList.remove('level-critical','level-high','level-medium','level-low','bg-success','bg-warning','bg-danger');
  let level = 'LOW', cls = 'level-low';
  if (crit > 0)          { level = 'CRITICAL'; cls = 'level-critical'; }
  else if (high > 0)     { level = 'HIGH';     cls = 'level-high'; }
  else if (open > 0)     { level = 'MEDIUM';   cls = 'level-medium'; }
  badge.className = `ms-3 badge ${cls}`;
  badge.textContent = `THREAT LEVEL: ${level}`;
}

/* ─────────── Socket: Sysmon ─────────── */
socket.on('sysmon_update', data => {
  const s = data.stats;
  document.getElementById('stat-sysmon-events').textContent = s.total_events.toLocaleString();
  document.getElementById('sys-total').textContent = s.total_events.toLocaleString();
  document.getElementById('sys-suspicious').textContent = s.suspicious_events;
  document.getElementById('sys-critical').textContent = s.critical_events;
  updateSysmonTable(data.recent_events || []);
  renderOverviewSysmon(data.recent_events || []);
});

function renderOverviewSysmon(events) {
  const el = document.getElementById('overview-sysmon-list');
  if (!el) return;
  const latest = [...events].slice(-10).reverse();
  if (!latest.length) { el.innerHTML = '<div class="text-muted p-2">이벤트 없음</div>'; return; }
  el.innerHTML = latest.map(ev => `
    <div class="sysmon-mini-row ${ev.suspicious ? 'suspicious' : ''}">
      <span class="ts">${(ev.timestamp||'').split(' ')[1] || ''}</span>
      <span class="eid">${ev.event_id}</span>
      <span class="ename" title="${escapeHtml(ev.event_name)}">${escapeHtml(ev.event_name)}</span>
      <span>${sevBadge(ev.severity)}</span>
    </div>`).join('');
}

socket.on('sysmon_alert', event => {
  // 의심 Sysmon 이벤트는 빨간 행으로 강조
  updateSysmonTable([event], true);
});

/* ─────────── Socket: AI 분석 (패널 제거 — 네비 배지만 갱신) ─────────── */
socket.on('ai_analysis', () => {
  const el = document.getElementById('stat-ai-analyses');
  if (el) el.textContent = parseInt(el.textContent || 0) + 1;
  const badge = document.getElementById('ai-status-badge');
  if (badge) {
    badge.textContent = 'AI 분석 완료';
    badge.className = 'badge bg-success';
    setTimeout(() => {
      badge.textContent = 'AI 대기중';
      badge.className = 'badge bg-secondary';
    }, 4000);
  }
});

/* ─────────── Socket: 지도 공격 ─────────── */
socket.on('map_attack', entry => {
  animateAttack(entry);
  prependAttackLog(entry);
  updateCountryChart(entry.src_country);
});

/* ════════════════════ 알림 패널 ════════════════════ */
let alertsDataTable = null;

function loadAlerts() {
  fetch('/api/alerts?limit=200')
    .then(r => r.json())
    .then(d => {
      const tbody = document.getElementById('alerts-tbody');
      tbody.innerHTML = '';
      d.alerts.forEach(a => prependAlertRow(a, false));
      if (!alertsDataTable) {
        alertsDataTable = $('#alerts-table').DataTable({
          order: [[0, 'desc']],
          pageLength: 20,
          language: { url: '' },
        });
      }
    });
}

/* 데모 모드에서 합성된 이벤트임을 알리는 회색 배지 */
function demoBadge(details) {
  return details && details.demo
    ? ' <span class="badge demo-badge" title="데모 모드에서 생성된 합성 이벤트 — 실제 침해 아님">데모</span>'
    : '';
}

function confBadge(alert) {
  const c = alert.confidence ?? alert.details?.confidence;
  if (c == null) return '';
  if (alert.details?.low_confidence) {
    return ` <span class="badge bg-orange" style="font-size:9px" title="신뢰도 ${Math.round(c*100)}% — 임계값 미만">오탐 의심</span>`;
  }
  const cls = c >= 0.75 ? 'bg-success' : 'bg-secondary';
  return ` <span class="badge ${cls}" style="font-size:9px" title="정탐 신뢰도">${Math.round(c*100)}%</span>`;
}

function prependAlertRow(alert, prepend = true) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  const statusColors = { OPEN: 'danger', ACK: 'warning', CLOSED: 'secondary' };
  const statusLabels = { OPEN: '미처리', ACK: '확인됨', CLOSED: '종료' };
  const row = document.createElement('tr');
  row.id = `alert-row-${alert.id}`;
  row.dataset.lowconf = alert.details?.low_confidence ? '1' : '0';   // 정탐만 필터용
  row.innerHTML = `
    <td>${escapeHtml(alert.timestamp)}</td>
    <td>${sevBadge(alert.severity)}</td>
    <td><span style="color:${threatColor(alert.threat_type)}">${escapeHtml(alert.threat_label)}</span>${confBadge(alert)}${demoBadge(alert.details)}</td>
    <td class="font-monospace">${escapeHtml(alert.src_ip)}</td>
    <td class="font-monospace">${escapeHtml(alert.dst_ip)}</td>
    <td>${escapeHtml(alert.description)}</td>
    <td><span class="badge bg-${statusColors[alert.status]}">${statusLabels[alert.status]}</span></td>
    <td>
      <button class="btn btn-xs btn-outline-info me-1" onclick="analyzeAlertAI(${alert.id})">
        <i class="fa fa-robot"></i>
      </button>
      <button class="btn btn-xs btn-outline-warning me-1" onclick="updateAlertStatus(${alert.id},'ACK')">확인</button>
      <button class="btn btn-xs btn-outline-secondary" onclick="updateAlertStatus(${alert.id},'CLOSED')">종료</button>
    </td>`;
  if (prepend && tbody.firstChild) {
    tbody.insertBefore(row, tbody.firstChild);
  } else {
    tbody.appendChild(row);
  }
}

function updateAlertStatus(id, status) {
  fetch(`/api/alerts/${id}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  }).then(() => {
    const row = document.getElementById(`alert-row-${id}`);
    if (row) {
      const badges = { OPEN:'danger', ACK:'warning', CLOSED:'secondary' };
      const labels = { OPEN:'미처리', ACK:'확인됨', CLOSED:'종료' };
      row.querySelector('td:nth-child(7)').innerHTML =
        `<span class="badge bg-${badges[status]}">${labels[status]}</span>`;
    }
    // ACK / CLOSED 모두 미처리 수에서 제외
    if (status === 'ACK' || status === 'CLOSED') {
      adjustOpenAlerts(-1);
    }
    if (status === 'CLOSED') {
      incEl('kpi-blocked');
    }
  });
}

/* 개요 카드 클릭 → 알림 패널로 이동하며 필터 적용 */
function filterAlerts(severity) {
  showPanel('alerts');
  // DataTables 초기화 후 필터 적용 (비동기)
  setTimeout(() => {
    if (alertsDataTable) {
      alertsDataTable.column(1).search(severity, false, false).draw();
    }
  }, 150);
}

function filterAlertsByStatus(statusLabel) {
  showPanel('alerts');
  const mapKo = { CLOSED: '종료', ACK: '확인됨', OPEN: '미처리' };
  const q = mapKo[statusLabel] || statusLabel;
  setTimeout(() => {
    if (alertsDataTable) {
      alertsDataTable.column(6).search(q, false, false).draw();
    }
  }, 150);
}

function prependOverviewAlert(alert) {
  const list = document.getElementById('recent-alerts-list');
  if (!list) return;
  const item = document.createElement('div');
  item.className = `alert-item ${alert.severity}`;
  item.innerHTML = `
    <div>${sevBadge(alert.severity)}</div>
    <div class="flex-fill">
      <span style="color:${threatColor(alert.threat_type)};font-weight:600">${escapeHtml(alert.threat_label)}</span>${demoBadge(alert.details)}
      <span class="text-muted ms-2">${escapeHtml(alert.src_ip)} → ${escapeHtml(alert.dst_ip)}</span>
      <div class="text-muted" style="font-size:11px">${escapeHtml(alert.description)}</div>
    </div>
    <div class="text-muted" style="font-size:10px;white-space:nowrap">${alert.timestamp.split(' ')[1]||alert.timestamp}</div>`;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 8) list.removeChild(list.lastChild);
}

function updateSeverityChart(sev) {
  const idx = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[sev];
  if (idx !== undefined) {
    sevChart.data.datasets[0].data[idx]++;
    sevChart.update('none');
  }
}

/* ════════════════════ 패킷 테이블 ════════════════════ */
let packetsInit = false;
let packetsTable = null;

function initPacketsTable() {
  if (!packetsInit) {
    packetsTable = $('#packets-table').DataTable({
      order: [[0, 'desc']],
      pageLength: 30,
      scrollY: '520px',
      scrollCollapse: true,
    });
    packetsInit = true;
  }
}

function updatePacketsTable(packets) {
  const tbody = document.getElementById('packets-tbody');
  if (!tbody || !packetsInit) return;
  packets.slice(-10).forEach(p => {
    const row = document.createElement('tr');
    row.style.color = '#e6edf3';
    row.innerHTML = `
      <td style="color:#e6edf3">${escapeHtml(p.time)}</td>
      <td style="color:#e6edf3">${escapeHtml(p.src_ip)}</td>
      <td style="color:#e6edf3">${escapeHtml(p.dst_ip)}</td>
      <td style="color:#e6edf3">${p.src_port || '-'}</td>
      <td style="color:#e6edf3">${p.dst_port || '-'}</td>
      <td><span style="color:${protoColor(p.protocol)};font-weight:600">${escapeHtml(p.protocol)}</span></td>
      <td style="color:#e6edf3">${p.length}</td>
      <td style="color:#e6edf3">${escapeHtml(p.info)}</td>`;
    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
  });
}

/* ════════════════════ 트래픽 차트 ════════════════════ */
let trafficInited = false;
let trafficPpsChart, trafficBpsChart, topTalkersChart, protoDist2Chart;

function initTrafficCharts() {
  if (trafficInited) return;
  trafficInited = true;

  const commonOpts = (label, color) => ({
    type: 'line',
    data: { labels: [], datasets: [{ label, data: [], borderColor: color,
      backgroundColor: color + '22', tension: 0.4, fill: true, pointRadius: 0, borderWidth: 2 }] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e', maxTicksLimit: 10, font:{size:10} }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
      },
    },
  });

  trafficPpsChart = new Chart(
    document.getElementById('traffic-pps-chart').getContext('2d'),
    commonOpts('패킷/초', '#39d0d8')
  );
  trafficBpsChart = new Chart(
    document.getElementById('traffic-bps-chart').getContext('2d'),
    commonOpts('바이트/초', '#9d79f2')
  );
  topTalkersChart = new Chart(
    document.getElementById('top-talkers-chart').getContext('2d'), {
      type: 'bar',
      data: { labels: [], datasets: [{ label: '패킷 수', data: [], backgroundColor: '#39d0d822', borderColor: '#39d0d8', borderWidth: 1 }] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10}, maxTicksLimit: 10 }, grid: { color: '#21262d' } },
        },
      },
    }
  );
  protoDist2Chart = new Chart(
    document.getElementById('proto-dist-chart').getContext('2d'), {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
        },
      },
    }
  );
}

function updateTrafficCharts(data) {
  if (!trafficInited) return;
  const hist = data.traffic_history || [];
  trafficPpsChart.data.labels = hist.map(h => h.time);
  trafficPpsChart.data.datasets[0].data = hist.map(h => h.pps);
  trafficPpsChart.update('none');

  trafficBpsChart.data.labels = hist.map(h => h.time);
  trafficBpsChart.data.datasets[0].data = hist.map(h => h.bps);
  trafficBpsChart.update('none');

  const tt = data.top_talkers || [];
  topTalkersChart.data.labels = tt.map(t => t[0]);
  topTalkersChart.data.datasets[0].data = tt.map(t => t[1]);
  topTalkersChart.update('none');

  const pd = data.protocol_dist || {};
  protoDist2Chart.data.labels = Object.keys(pd);
  protoDist2Chart.data.datasets[0].data = Object.values(pd);
  protoDist2Chart.data.datasets[0].backgroundColor = Object.keys(pd).map(protoColor);
  protoDist2Chart.update('none');
}

/* ════════════════════ SYSMON 테이블 ════════════════════ */
let sysmonInit = false;
let sysmonDT = null;

function initSysmonTable() {
  if (!sysmonInit) {
    sysmonDT = $('#sysmon-table').DataTable({
      order: [[0, 'desc']],
      pageLength: 25,
      scrollY: '420px',
      scrollCollapse: true,
    });
    sysmonInit = true;
  }
}

function updateSysmonTable(events, highlight = false) {
  const tbody = document.getElementById('sysmon-tbody');
  if (!tbody) return;
  events.forEach(ev => {
    const row = document.createElement('tr');
    row.style.color = '#e6edf3';
    if (ev.suspicious || highlight) row.style.background = 'rgba(248,81,73,.08)';
    row.innerHTML = `
      <td style="color:#e6edf3">${escapeHtml(ev.timestamp)}</td>
      <td style="color:#e6edf3">${ev.event_id}</td>
      <td style="color:#e6edf3">${escapeHtml(ev.event_name)}</td>
      <td>${sevBadge(ev.severity)}</td>
      <td class="font-monospace text-truncate" style="max-width:120px;color:#e6edf3" title="${escapeHtml(ev.process||'')}">${escapeHtml(ev.process||'-')}</td>
      <td class="text-truncate" style="max-width:240px;color:#e6edf3" title="${escapeHtml(ev.message)}">${escapeHtml(ev.message)}</td>
      <td>${ev.suspicious ? '<span class="badge bg-danger">의심</span>' : ''}</td>`;
    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
  });
}

/* ════════════════════ AI 분석 (패널은 제거됨 — 알림 테이블에서만 호출) ════════════════════ */
function analyzeAlertAI(alertId) {
  fetch(`/api/ai/analyze/alert/${alertId}`, { method: 'POST' })
    .then(r => r.json())
    .then(d => {
      const r = d.result || {};
      const msg = r.summary || r.raw_response || JSON.stringify(r, null, 2);
      alert(`[AI 분석 결과]\n\n${msg}`);
    });
}

function analyzeTrafficAI() {
  fetch('/api/ai/analyze/traffic', { method: 'POST' })
    .then(r => r.json())
    .then(d => {
      const r = d.result || {};
      const msg = r.summary || r.raw_response || JSON.stringify(r, null, 2);
      alert(`[AI 트래픽 분석]\n\n${msg}`);
    });
}

/* ════════════════════ 공격 지도 (3D 지구본) ════════════════════ */
let globe = null;
let globeInited = false;
const countryCounter = {};
let countryChart = null;

// Globe.gl 데이터 버퍼
let _globeArcs = [];
let _globeRings = [];
let _globePoints = [];

const DEFENDER = { lat: 37.5665, lng: 126.9780, label: 'Seoul (방어 서버)' };

function initMap() {
  if (globeInited) return;
  const el = document.getElementById('attack-globe');
  if (!el || typeof Globe === 'undefined') return;
  globeInited = true;

  globe = Globe()(el)
    .backgroundColor('rgba(0,0,0,0)')       // 패널 그라디언트가 우주 배경으로 비침
    .showGlobe(true)
    .showGraticules(false)
    .atmosphereColor('#39d0d8')
    .atmosphereAltitude(0.18)
    .showAtmosphere(true)
    // 대륙을 점(hex dot)으로 그린 사이버 점묘 지구본
    .hexPolygonsData([])
    .hexPolygonResolution(3)
    .hexPolygonMargin(0.28)
    .hexPolygonUseDots(true)
    .hexPolygonAltitude(0.003)
    .hexPolygonColor(() => 'rgba(92,173,208,0.55)')
    // Arcs (공격 궤적)
    .arcsData(_globeArcs)
    .arcStartLat(d => d.startLat).arcStartLng(d => d.startLng)
    .arcEndLat(d => d.endLat).arcEndLng(d => d.endLng)
    .arcColor(d => d.color)
    .arcStroke(0.4)
    .arcDashLength(0.35).arcDashGap(1.2)
    .arcDashInitialGap(() => 1)
    .arcDashAnimateTime(1800)
    .arcAltitudeAutoScale(0.45)
    // Rings (임팩트/레이더 펄스)
    .ringsData(_globeRings)
    .ringColor(d => t => `rgba(${d.rgb},${1 - t})`)
    .ringMaxRadius(d => d.maxR || 5)
    .ringPropagationSpeed(d => d.speed || 3)
    .ringRepeatPeriod(d => d.repeat || 800)
    .ringAltitude(0.008)
    // Points (공격자/방어자 마커)
    .pointsData(_globePoints)
    .pointLat(d => d.lat).pointLng(d => d.lng)
    .pointColor(d => d.color)
    .pointAltitude(d => d.alt || 0.01)
    .pointRadius(d => d.radius || 0.3)
    .pointLabel(d => d.label || '');

  // 크기 맞추기
  const resize = () => {
    globe.width(el.clientWidth);
    globe.height(el.clientHeight);
  };
  resize();
  window.addEventListener('resize', resize);

  // 짙은 남색 바다 구체 (사진 텍스처 대신 단색 머티리얼)
  if (typeof THREE !== 'undefined') {
    const gm = globe.globeMaterial();
    gm.color = new THREE.Color(0x081726);
    gm.emissive = new THREE.Color(0x0a2036);
    gm.emissiveIntensity = 0.35;
    gm.shininess = 0.3;
  }

  // 국가 폴리곤을 점 패턴으로 로드 (로컬 번들 GeoJSON)
  fetch('/static/data/countries-110m.geojson')
    .then(r => r.json())
    .then(geo => { if (globe && geo && geo.features) globe.hexPolygonsData(geo.features); })
    .catch(() => { /* 실패 시 바다 구체만 표시 */ });

  // 한국 중심 고정 (자동 회전 OFF)
  const controls = globe.controls();
  controls.autoRotate = false;
  controls.enableZoom = true;
  globe.pointOfView({ lat: DEFENDER.lat, lng: DEFENDER.lng, altitude: 2.2 }, 0);

  // 방어자(서울) 마커 + 상시 레이더 펄스 링
  _globePoints.push({
    lat: DEFENDER.lat, lng: DEFENDER.lng, color: '#39d0d8',
    radius: 0.55, alt: 0.012, label: `<b style="color:#39d0d8">🛡 ${DEFENDER.label}</b>`
  });
  _globeRings.push({
    lat: DEFENDER.lat, lng: DEFENDER.lng,
    rgb: '57,208,216', maxR: 4, speed: 1.8, repeat: 1400,
  });
  globe.pointsData([..._globePoints]).ringsData([..._globeRings]);
}

function animateAttack(entry) {
  if (!globeInited || !globe) return;

  const sevColors = {
    CRITICAL: '#ff2d5e', HIGH: '#ff7b00', MEDIUM: '#ffd23f', LOW: '#00e1ff'
  };
  const sevRgb = {
    CRITICAL: '255,45,94', HIGH: '255,123,0', MEDIUM: '255,210,63', LOW: '0,225,255'
  };
  const color = sevColors[entry.severity] || '#8b949e';
  const rgb   = sevRgb[entry.severity]   || '139,148,158';

  // Arc (미사일 궤적)
  const arc = {
    startLat: entry.src_lat, startLng: entry.src_lng,
    endLat:   entry.dst_lat || DEFENDER.lat,
    endLng:   entry.dst_lng || DEFENDER.lng,
    color:    [color + '00', color, color + '00'],  // 그라디언트
  };
  _globeArcs.push(arc);
  if (_globeArcs.length > 40) _globeArcs.shift();
  globe.arcsData([..._globeArcs]);

  // 출발지 마커 (공격자)
  const atk = {
    lat: entry.src_lat, lng: entry.src_lng, color,
    radius: 0.35, alt: 0.008,
    label: `<b style="color:${color}">⚠ ${entry.src_country || ''}</b> ${entry.src_city || ''}<br/>
            IP: <span style="font-family:monospace">${entry.ip}</span><br/>
            유형: <b>${entry.threat_type}</b><br/>등급: ${entry.severity}`,
  };
  _globePoints.push(atk);
  if (_globePoints.length > 80) _globePoints.splice(1, 1);  // 0번은 방어자
  globe.pointsData([..._globePoints]);

  // 임팩트 링 (도착 후 트리거)
  setTimeout(() => {
    const impact = {
      lat: arc.endLat, lng: arc.endLng, rgb,
      maxR: 6, speed: 5, repeat: 0,
    };
    _globeRings.push(impact);
    globe.ringsData([..._globeRings]);
    setTimeout(() => {
      const i = _globeRings.indexOf(impact);
      if (i > -1) _globeRings.splice(i, 1);
      globe.ringsData([..._globeRings]);
    }, 2500);
  }, 1600);

  // 출발지 마커는 8초 후 제거
  setTimeout(() => {
    const i = _globePoints.indexOf(atk);
    if (i > -1) _globePoints.splice(i, 1);
    globe.pointsData([..._globePoints]);
  }, 8000);
}

function prependAttackLog(entry) {
  const list = document.getElementById('attack-log');
  if (!list) return;
  const item = document.createElement('div');
  item.className = 'attack-log-item';
  item.innerHTML = `
    <span class="country">${escapeHtml(entry.src_country)} &rarr; Seoul</span>
    <span class="meta">${escapeHtml(entry.threat_type)} | ${escapeHtml(entry.ip)}</span>
    <span class="meta">${escapeHtml(entry.timestamp)} | ${sevBadge(entry.severity)}</span>`;
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 50) list.removeChild(list.lastChild);
}

function updateCountryChart(country) {
  countryCounter[country] = (countryCounter[country] || 0) + 1;
  const sorted = Object.entries(countryCounter).sort((a, b) => b[1] - a[1]).slice(0, 10);

  if (!countryChart) {
    const ctx = document.getElementById('country-chart')?.getContext('2d');
    if (!ctx) return;
    countryChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: sorted.map(s => s[0]),
        datasets: [{ data: sorted.map(s => s[1]), backgroundColor: '#f8514944', borderColor: '#f85149', borderWidth: 1 }],
      },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#21262d' } },
        },
      },
    });
  } else {
    countryChart.data.labels = sorted.map(s => s[0]);
    countryChart.data.datasets[0].data = sorted.map(s => s[1]);
    countryChart.update('none');
  }
}

/* ════════════════════ ML 자체 모델 ════════════════════ */
let rfProbaChart   = null;
let lstmErrChart   = null;
let ifScoreChart   = null;
let rlThreshChart  = null;
let mlPanelInited  = false;

function initMLCharts() {
  if (mlPanelInited) return;
  mlPanelInited = true;

  rfProbaChart = new Chart(document.getElementById('rf-proba-chart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: ['정상','DDoS','포트스캔','브루트포스','데이터유출','C2'],
      datasets: [{ data: [0,0,0,0,0,0],
        backgroundColor: ['#3fb95044','#f8514944','#f7900044','#e3b34144','#58a6ff44','#9d79f244'],
        borderColor:     ['#3fb950','#f85149','#f79000','#e3b341','#58a6ff','#9d79f2'],
        borderWidth: 2 }],
    },
    options: {
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { min:0, max:100, ticks:{ color:'#8b949e', font:{size:10} }, grid:{color:'#21262d'} },
        x: { ticks:{ color:'#8b949e', font:{size:9} }, grid:{color:'#21262d'} },
      },
    },
  });

  lstmErrChart = new Chart(document.getElementById('lstm-error-chart').getContext('2d'), {
    type: 'line',
    data: { labels:[], datasets:[
      { label:'재구성 오차', data:[], borderColor:'#f85149', backgroundColor:'#f8514922',
        tension:0.4, fill:true, pointRadius:3, borderWidth:2 },
      { label:'임계값', data:[], borderColor:'#e3b341', borderDash:[5,4],
        pointRadius:0, borderWidth:1.5 },
    ]},
    options: {
      animation:false,
      plugins:{ legend:{ labels:{ color:'#8b949e', font:{size:10} } } },
      scales: {
        x:{ ticks:{color:'#8b949e',font:{size:9},maxTicksLimit:8}, grid:{color:'#21262d'} },
        y:{ ticks:{color:'#8b949e',font:{size:9}}, grid:{color:'#21262d'} },
      },
    },
  });

  ifScoreChart = new Chart(document.getElementById('if-score-chart').getContext('2d'), {
    type: 'line',
    data: { labels:[], datasets:[
      { label:'IF 점수', data:[], borderColor:'#39d0d8', backgroundColor:'#39d0d811',
        tension:0.3, fill:true, pointRadius:2, borderWidth:2 },
    ]},
    options: {
      animation:false,
      plugins:{ legend:{ display:false } },
      scales: {
        x:{ ticks:{color:'#8b949e',font:{size:9},maxTicksLimit:8}, grid:{color:'#21262d'} },
        y:{ ticks:{color:'#8b949e',font:{size:9}}, grid:{color:'#21262d'} },
      },
    },
  });

  rlThreshChart = new Chart(document.getElementById('rl-threshold-chart').getContext('2d'), {
    type: 'line',
    data: { labels:[], datasets:[
      { label:'임계값 배율', data:[], borderColor:'#e3b341', backgroundColor:'#e3b34122',
        tension:0.3, fill:true, pointRadius:2, borderWidth:2 },
    ]},
    options: {
      animation:false,
      plugins:{ legend:{ display:false } },
      scales: {
        x:{ ticks:{color:'#8b949e',font:{size:9},maxTicksLimit:8}, grid:{color:'#21262d'} },
        y:{ min:0.2, max:3.2, ticks:{color:'#8b949e',font:{size:9}}, grid:{color:'#21262d'} },
      },
    },
  });

  loadMLStatus();
}

/* Socket 이벤트: ML 모델 준비 완료 */
socket.on('ml_model_ready', data => {
  document.getElementById('ml-status-badge').textContent = '운영 중';
  console.log('[ML]', data.message, data.models);
});

/* Socket 이벤트: ML 분석 결과 */
socket.on('ml_analysis', data => {
  updateMLDisplay(data);
  appendMLLog(data);
  updateOverviewML(data);
});

function updateOverviewML(data) {
  // IF
  const ifAnom = data.isolation_forest?.anomaly;
  const ifB = document.getElementById('ov-if-badge');
  if (ifB) ifB.className = 'badge me-1 ' + (ifAnom ? 'bg-danger' : 'bg-success');
  const ifC = document.getElementById('ov-if-anom');
  if (ifC && ifAnom) ifC.textContent = parseInt(ifC.textContent || 0) + 1;

  // RF
  const rfLabel = data.random_forest?.label;
  const rfConf  = data.random_forest?.confidence;
  const rfEl = document.getElementById('ov-rf-last');
  if (rfEl && rfLabel) {
    const col = rfLabel === 'NORMAL' ? '#3fb950' : '#f85149';
    rfEl.innerHTML = `<span style="color:${col}">${rfLabel}</span> (${rfConf}%)`;
  }

  // LSTM
  const lstmAnom = data.lstm?.anomaly;
  const lstmB = document.getElementById('ov-lstm-badge');
  if (lstmB) lstmB.className = 'badge me-1 ' + (lstmAnom ? 'bg-danger' : 'bg-success');
  const lstmC = document.getElementById('ov-lstm-anom');
  if (lstmC && lstmAnom) lstmC.textContent = parseInt(lstmC.textContent || 0) + 1;

  // RL
  const mult = data.rl?.threshold_multiplier;
  const rlEl = document.getElementById('ov-rl-mult');
  if (rlEl && mult !== undefined) rlEl.textContent = mult;

  // ML 이상탐지 KPI
  if (ifAnom || lstmAnom) {
    const el = document.getElementById('kpi-ml-anomaly');
    if (el) el.textContent = parseInt(el.textContent || 0) + 1;
  }
}

function updateMLDisplay(data) {
  // IF
  const ifRes = data.isolation_forest || {};
  if (ifRes.score !== undefined) {
    const score = ifRes.score;
    if (ifScoreChart) {
      const ts = data.timestamp?.split(' ')[1] || '';
      ifScoreChart.data.labels.push(ts);
      ifScoreChart.data.datasets[0].data.push(score);
      if (ifScoreChart.data.labels.length > 30) {
        ifScoreChart.data.labels.shift();
        ifScoreChart.data.datasets[0].data.shift();
      }
      ifScoreChart.update('none');
    }
  }

  // RF
  const rfRes = data.random_forest || {};
  if (rfRes.probabilities && rfProbaChart) {
    const labels = ['NORMAL','DDOS','PORT_SCAN','BRUTE_FORCE','DATA_EXFIL','MALWARE_C2'];
    rfProbaChart.data.datasets[0].data = labels.map(l => rfRes.probabilities[l] || 0);
    rfProbaChart.update('none');
    const verdict = document.getElementById('rf-verdict');
    if (verdict) {
      const cls = rfRes.label || '-';
      const conf = rfRes.confidence || 0;
      const col = cls === 'NORMAL' ? '#3fb950' : '#f85149';
      verdict.innerHTML = `예측: <strong style="color:${col}">${cls}</strong> (신뢰도: ${conf}%)`;
    }
  }

  // LSTM
  const lstmRes = data.lstm || {};
  if (lstmRes.reconstruction_error !== undefined && lstmErrChart) {
    const ts = data.timestamp?.split(' ')[1] || '';
    lstmErrChart.data.labels.push(ts);
    lstmErrChart.data.datasets[0].data.push(lstmRes.reconstruction_error);
    lstmErrChart.data.datasets[1].data.push(lstmRes.threshold);
    if (lstmErrChart.data.labels.length > 30) {
      lstmErrChart.data.labels.shift();
      lstmErrChart.data.datasets[0].data.shift();
      lstmErrChart.data.datasets[1].data.shift();
    }
    lstmErrChart.update('none');
    const verdict = document.getElementById('lstm-verdict');
    if (verdict) {
      const col = lstmRes.anomaly ? '#f85149' : '#3fb950';
      verdict.innerHTML = `오차: <strong style="color:${col}">${lstmRes.reconstruction_error?.toFixed(6)}</strong> (임계: ${lstmRes.threshold?.toFixed(6)})`;
    }
  }

  // RL
  const rlRes = data.rl || {};
  if (rlRes.threshold_multiplier !== undefined) {
    const el = document.getElementById('ml-rl-threshold');
    if (el) el.textContent = rlRes.threshold_multiplier + 'x';
    const ts = data.timestamp?.split(' ')[1] || '';
    if (rlThreshChart) {
      rlThreshChart.data.labels.push(ts);
      rlThreshChart.data.datasets[0].data.push(rlRes.threshold_multiplier);
      if (rlThreshChart.data.labels.length > 30) {
        rlThreshChart.data.labels.shift();
        rlThreshChart.data.datasets[0].data.shift();
      }
      rlThreshChart.update('none');
    }
    const actionEl = document.getElementById('rl-action-label');
    if (actionEl) actionEl.textContent = `마지막 행동: ${rlRes.action} | ε=${rlRes.epsilon}`;
    const epsEl = document.getElementById('rl-epsilon');
    if (epsEl) epsEl.textContent = rlRes.epsilon;
  }

  // 통계 업데이트
  const s = data;
  if (s.isolation_forest?.anomaly) {
    const el = document.getElementById('ml-if-anomalies');
    if (el) el.textContent = parseInt(el.textContent || 0) + 1;
  }
  if (s.lstm?.anomaly) {
    const el = document.getElementById('ml-lstm-anomalies');
    if (el) el.textContent = parseInt(el.textContent || 0) + 1;
  }
}

function appendMLLog(data) {
  const log = document.getElementById('ml-log');
  if (!log) return;
  const sev = data.summary?.severity || 'NORMAL';
  const threats = (data.summary?.threats || []).join(', ') || '없음';
  const rf = data.random_forest?.label || '-';
  const conf = data.random_forest?.confidence || 0;
  const div = document.createElement('div');
  div.className = 'd-flex gap-3 py-1 border-bottom border-secondary align-items-center';
  div.setAttribute('style', 'color:#e6edf3');
  div.innerHTML = `
    <span style="min-width:60px;color:#e6edf3">${data.timestamp?.split(' ')[1] || ''}</span>
    <span>${sevBadge(sev)}</span>
    <span style="color:#e6edf3">RF: <strong style="color:${rf==='NORMAL'?'#3fb950':'#f85149'}">${rf}</strong>(${conf}%)</span>
    <span style="color:#e6edf3">탐지: ${threats}</span>`;
  log.insertBefore(div, log.firstChild);
  while (log.children.length > 30) log.removeChild(log.lastChild);
}

function loadMLStatus() {
  fetch('/api/ml/status').then(r => r.json()).then(d => {
    const s = d.stats || {};
    const rl = d.rl || {};
    const el = document.getElementById('ml-status-badge');
    if (el) el.textContent = s.model_status || '-';
    const rle = document.getElementById('ml-rl-threshold');
    if (rle) rle.textContent = (rl.threshold_multiplier || 1.0) + 'x';
    if (document.getElementById('ml-if-anomalies'))
      document.getElementById('ml-if-anomalies').textContent = s.if_anomalies || 0;
    if (document.getElementById('ml-lstm-anomalies'))
      document.getElementById('ml-lstm-anomalies').textContent = s.lstm_anomalies || 0;
  });
}

function triggerMLAnalysis() {
  fetch('/api/ml/analyze', { method: 'POST' })
    .then(r => r.json())
    .then(d => { updateMLDisplay(d); appendMLLog(d); });
}

function sendFeedback(isFP) {
  fetch('/api/ml/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ is_false_positive: isFP }),
  });
}

/* ════════════════════ MITRE ATT&CK ════════════════════ */
let mitreMatrixData = null;

function loadMitreMatrix() {
  fetch('/api/mitre/matrix')
    .then(r => r.json())
    .then(d => {
      mitreMatrixData = d;
      renderMitreMatrix(d);
      updateMitreStats(d);
    });
  loadMitreTop();
  loadMitreRecent();
  loadMitreLog();
}

/* ── 상세 MITRE 로그 테이블 ── */
const mitreLogBuffer = [];
const MITRE_LOG_MAX = 200;

function loadMitreLog() {
  fetch('/api/mitre/recent?limit=' + MITRE_LOG_MAX)
    .then(r => r.json())
    .then(d => {
      mitreLogBuffer.length = 0;
      (d.events || []).forEach(e => mitreLogBuffer.push(e));
      renderMitreLog();
    });
}

function renderMitreLog() {
  const tbody = document.getElementById('mitre-log-tbody');
  if (!tbody) return;
  const sevFilter = (document.getElementById('mitre-log-sev-filter')?.value || '').trim();
  const kwFilter  = (document.getElementById('mitre-log-filter')?.value || '').trim().toLowerCase();

  const filtered = mitreLogBuffer.filter(e => {
    if (sevFilter && (e.severity || '').toUpperCase() !== sevFilter) return false;
    if (kwFilter) {
      const hay = `${e.src_ip||''} ${e.dst_ip||''} ${e.technique_id||''} ${e.technique_ko||''} ${e.description||''}`.toLowerCase();
      if (!hay.includes(kwFilter)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center p-3">일치하는 이벤트 없음</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.slice(0, 200).map(e => mitreLogRow(e)).join('');
}

function mitreLogRow(e) {
  const sev = (e.severity || 'MEDIUM').toUpperCase();
  const sevCls = sev === 'CRITICAL' ? 'badge bg-danger'
              : sev === 'HIGH'     ? 'badge bg-orange'
              : sev === 'MEDIUM'   ? 'badge bg-warning text-dark'
              : 'badge bg-secondary';
  const time = (e.timestamp || '').split(' ')[1] || e.timestamp || '';
  return `<tr style="color:#e6edf3">
    <td style="font-size:11px;color:#e6edf3">${time}</td>
    <td><span class="${sevCls}" style="font-size:10px">${sev}</span></td>
    <td><span class="small" style="color:#e6edf3">${e.tactic_ko || e.tactic_id || ''}</span></td>
    <td>
      <a href="javascript:;" onclick="showTechniqueDetail('${e.technique_id}')" class="text-info font-monospace me-1">${e.technique_id}</a>
      <span class="small" style="color:#e6edf3">${e.technique_ko || ''}</span>
    </td>
    <td class="font-monospace small" style="color:#e6edf3">${e.src_ip || '-'}</td>
    <td class="font-monospace small" style="color:#e6edf3">${e.dst_ip || '-'}</td>
    <td class="small" style="color:#e6edf3">${e.process || '-'}</td>
    <td class="small" style="color:#e6edf3">${escapeHtml(e.description || '')}</td>
  </tr>`;
}

document.addEventListener('DOMContentLoaded', () => {
  const sf = document.getElementById('mitre-log-sev-filter');
  const kf = document.getElementById('mitre-log-filter');
  if (sf) sf.addEventListener('change', renderMitreLog);
  if (kf) kf.addEventListener('input', renderMitreLog);
});

function renderMitreMatrix(data) {
  const container = document.getElementById('mitre-matrix-container');
  if (!container) return;

  const tactics = data.tactics || [];
  let html = '<div class="mitre-matrix">';

  tactics.forEach(tac => {
    html += `<div class="mitre-tactic">
      <div class="mitre-tactic-header" title="${tac.name} (${tac.id})">
        <span class="t-ko">${tac.ko}</span>
        <span class="t-en">${tac.name}</span>
        <span class="t-count">${tac.total}</span>
      </div>`;

    (tac.techniques || []).forEach(tech => {
      const count = tech.count || 0;
      let hitClass = '';
      if (count > 0 && count < 3)        hitClass = 'hit-low';
      else if (count < 10)                hitClass = 'hit-med';
      else if (count >= 10)               hitClass = 'hit-high';

      html += `<div class="mitre-technique clickable ${hitClass}"
                    title="${tech.name} — 탐지 ${count}건 · 클릭 시 상세"
                    onclick="showTechniqueDetail('${tech.id}')"
                    data-tactic="${tac.id}" data-technique="${tech.id}">
        <div class="tech-id">${tech.id}</div>
        <div class="tech-name">${tech.ko}</div>
        ${count > 0 ? `<div class="tech-count">${count}</div>` : ''}
      </div>`;
    });

    html += '</div>';
  });

  html += '</div>';
  container.innerHTML = html;
}

/* ── Technique 상세 모달 ── */
function showTechniqueDetail(techId) {
  const modalEl = document.getElementById('mitreDetailModal');
  if (!modalEl) return;
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  const body  = document.getElementById('mitre-detail-body');
  const title = document.getElementById('mitre-detail-title');
  const ref   = document.getElementById('mitre-detail-ref');
  title.innerHTML = `<i class="fa fa-crosshairs text-danger me-2"></i>${techId} 로딩 중...`;
  body.innerHTML = '<div class="text-center text-muted py-5"><i class="fa fa-spinner fa-spin fa-2x"></i></div>';
  ref.href = `https://attack.mitre.org/techniques/${techId}/`;
  modal.show();

  fetch(`/api/mitre/technique/${techId}`)
    .then(r => r.json())
    .then(d => {
      if (!d.found) {
        body.innerHTML = `<div class="alert alert-warning">${d.message || '해당 Technique 정보가 없습니다.'}</div>`;
        return;
      }
      title.innerHTML = `<i class="fa fa-crosshairs text-danger me-2"></i>${d.technique_id} · ${d.technique_ko}
        <span class="badge bg-secondary ms-2" style="font-size:11px">${d.tactic_id} · ${d.tactic_ko}</span>`;
      ref.href = d.reference_url;

      const sev = d.severity_dist || {};
      const sevHtml = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => {
        const c = sev[s] || 0;
        const cls = s === 'CRITICAL' ? 'bg-danger'
                 : s === 'HIGH'     ? 'bg-orange'
                 : s === 'MEDIUM'   ? 'bg-warning text-dark'
                 : 'bg-secondary';
        return c ? `<span class="badge ${cls} me-1">${s} ${c}</span>` : '';
      }).join('');

      const rowHtml = arr => arr.length
        ? arr.map(x => `<tr><td class="font-monospace">${x.ip||x.name}</td><td class="text-end">${x.count}</td></tr>`).join('')
        : '<tr><td colspan="2" class="text-muted text-center">-</td></tr>';

      const recentHtml = (d.recent||[]).length
        ? d.recent.map(e => {
            const sevCls = e.severity === 'CRITICAL' ? 'text-danger'
                        : e.severity === 'HIGH'     ? 'text-orange'
                        : 'text-warning';
            return `<tr>
              <td class="text-muted" style="font-size:11px">${e.timestamp.split(' ')[1] || e.timestamp}</td>
              <td class="${sevCls}">${e.severity||'-'}</td>
              <td class="font-monospace">${e.src_ip||'-'}</td>
              <td class="font-monospace">${e.dst_ip||'-'}</td>
              <td>${escapeHtml(e.description||'')}</td>
            </tr>`;
          }).join('')
        : '<tr><td colspan="5" class="text-muted text-center">기록 없음</td></tr>';

      const defenseHtml = (d.defense||[]).length
        ? '<ul class="mb-0 ps-3">' + d.defense.map(x => `<li>${escapeHtml(x)}</li>`).join('') + '</ul>'
        : '<div class="text-muted">권고사항 없음</div>';

      body.innerHTML = `
        <div class="mb-3" style="color:#e6edf3">${escapeHtml(d.description||'')}</div>
        <div class="row g-3 mb-3">
          <div class="col-sm-4"><div class="stat-card stat-sm border-danger">
            <div class="stat-value">${(d.total_count||0).toLocaleString()}</div>
            <div class="stat-label">총 탐지 건수</div>
          </div></div>
          <div class="col-sm-8"><div class="p-2" style="background:rgba(255,255,255,.03);border-radius:6px">
            <div class="small mb-1" style="color:#e6edf3">심각도 분포</div>
            <div>${sevHtml || '<span style="color:#e6edf3">-</span>'}</div>
          </div></div>
        </div>

        <div class="row g-3 mb-3">
          <div class="col-md-4">
            <h6 class="text-cyan"><i class="fa fa-location-dot me-1"></i>TOP 출발 IP</h6>
            <table class="table table-dark table-sm table-striped mb-0"><tbody>${rowHtml(d.top_src_ips||[])}</tbody></table>
          </div>
          <div class="col-md-4">
            <h6 class="text-orange"><i class="fa fa-crosshairs me-1"></i>TOP 목적 IP</h6>
            <table class="table table-dark table-sm table-striped mb-0"><tbody>${rowHtml(d.top_dst_ips||[])}</tbody></table>
          </div>
          <div class="col-md-4">
            <h6 class="text-purple"><i class="fa fa-microchip me-1"></i>TOP 프로세스</h6>
            <table class="table table-dark table-sm table-striped mb-0"><tbody>${rowHtml(d.top_processes||[])}</tbody></table>
          </div>
        </div>

        <h6 class="text-info"><i class="fa fa-clock-rotate-left me-1"></i>최근 이벤트 (상위 30건)</h6>
        <div style="max-height:260px;overflow-y:auto" class="mb-3">
          <table class="table table-dark table-sm table-hover mb-0">
            <thead><tr><th>시각</th><th>심각도</th><th>출발 IP</th><th>목적 IP</th><th>설명</th></tr></thead>
            <tbody>${recentHtml}</tbody>
          </table>
        </div>

        <h6 class="text-success"><i class="fa fa-shield me-1"></i>방어 권고</h6>
        ${defenseHtml}
      `;
    })
    .catch(e => {
      body.innerHTML = `<div class="alert alert-danger">로딩 오류: ${e}</div>`;
    });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ════════════════════ 재사용 SVG 차트 헬퍼 (외부 라이브러리 없음) ════════════════════ */
// 도넛 차트: segs = [{label, value, color}]
function svgDonut(elId, segs, centerTop, centerSub) {
  const svg = document.getElementById(elId);
  if (!svg) return;
  const W = svg.clientWidth || 260, H = svg.getAttribute('height') * 1 || 170;
  const cx = Math.min(90, W / 3), cy = H / 2, r = Math.min(cy - 12, 58), sw = 20;
  const total = segs.reduce((a, s) => a + (s.value || 0), 0);
  const C = 2 * Math.PI * r;
  let off = 0, ring = '';
  if (total > 0) {
    segs.forEach(s => {
      const frac = (s.value || 0) / total;
      if (frac <= 0) return;
      const len = frac * C;
      ring += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${sw}"
        stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 ${cx} ${cy})"/>`;
      off += len;
    });
  } else {
    ring = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#21262d" stroke-width="${sw}"/>`;
  }
  const center = `<text x="${cx}" y="${cy - 2}" text-anchor="middle" font-size="20" font-weight="800" fill="#e6edf3">${escapeHtml(centerTop ?? total)}</text>
    <text x="${cx}" y="${cy + 15}" text-anchor="middle" font-size="10" fill="#8b949e">${escapeHtml(centerSub || '')}</text>`;
  const lx = cx + r + sw + 6;
  let legend = '';
  segs.forEach((s, i) => {
    const ly = cy - segs.length * 11 + i * 22 + 6;
    const pct = total ? Math.round((s.value || 0) / total * 100) : 0;
    legend += `<rect x="${lx}" y="${ly - 9}" width="11" height="11" rx="2" fill="${s.color}"/>
      <text x="${lx + 17}" y="${ly}" font-size="11" fill="#c9d1d9">${escapeHtml(s.label)}</text>
      <text x="${lx + 17}" y="${ly + 13}" font-size="10" fill="#8b949e">${(s.value || 0).toLocaleString()} · ${pct}%</text>`;
  });
  svg.innerHTML = ring + center + legend;
}

// 가로 막대: items = [{label, value, color}]
function svgHBars(elId, items, unit) {
  const svg = document.getElementById(elId);
  if (!svg) return;
  const W = svg.clientWidth || 300;
  const rowH = 26, padL = 96, padR = 46, top = 6;
  const H = Math.max(40, top * 2 + items.length * rowH);
  svg.setAttribute('height', H);
  if (!items.length) {
    svg.innerHTML = `<text x="${W / 2}" y="26" text-anchor="middle" font-size="11" fill="#8b949e">데이터 없음</text>`;
    return;
  }
  const max = Math.max(1, ...items.map(i => i.value || 0));
  const barMax = W - padL - padR;
  let out = '';
  items.forEach((it, i) => {
    const y = top + i * rowH;
    const w = Math.max(2, (it.value || 0) / max * barMax);
    out += `<text x="${padL - 8}" y="${y + 15}" text-anchor="end" font-size="11" fill="#c9d1d9">${escapeHtml((it.label ?? '').toString().slice(0, 16))}</text>
      <rect x="${padL}" y="${y + 4}" width="${barMax}" height="15" rx="3" fill="#161b22"/>
      <rect x="${padL}" y="${y + 4}" width="${w}" height="15" rx="3" fill="${it.color || 'var(--cyan)'}"/>
      <text x="${padL + w + 6}" y="${y + 15}" font-size="11" font-weight="700" fill="#e6edf3">${(it.value || 0).toLocaleString()}${unit || ''}</text>`;
  });
  svg.innerHTML = out;
}

function updateMitreStats(data) {
  const total = data.total_mapped || 0;
  const unique = data.unique_techniques || 0;
  document.getElementById('mitre-total').textContent = total.toLocaleString();
  document.getElementById('mitre-unique').textContent = unique;

  const totalTechniques = (data.tactics || [])
    .reduce((a, t) => a + (t.techniques?.length || 0), 0);
  const coverage = totalTechniques
    ? ((unique / totalTechniques) * 100).toFixed(1)
    : 0;
  document.getElementById('mitre-coverage').textContent = coverage + '%';
}

function loadMitreTop() {
  fetch('/api/mitre/top?top=10')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('mitre-top-list');
      if (!el) return;
      const top = d.top || [];
      if (!top.length) {
        el.innerHTML = '<div class="text-muted p-2">아직 탐지된 Technique 없음</div>';
        return;
      }
      const max = top[0].count;
      el.innerHTML = top.map((t, i) => {
        const pct = max ? (t.count / max * 100).toFixed(0) : 0;
        return `<div class="mitre-top-item">
          <span class="rank">#${i + 1}</span>
          <span class="tech-code font-monospace">${t.technique_id}</span>
          <span class="tech-name">${t.ko} <span class="text-muted">(${t.tactic_name})</span></span>
          <div class="bar-wrap"><div class="bar" style="width:${pct}%"></div></div>
          <span class="count">${t.count}</span>
        </div>`;
      }).join('');
    });
}

function loadMitreRecent() {
  fetch('/api/mitre/recent?limit=30')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('mitre-recent-list');
      if (!el) return;
      const events = d.events || [];
      if (!events.length) {
        el.innerHTML = '<div class="text-muted p-2">최근 매핑된 이벤트 없음</div>';
        return;
      }
      el.innerHTML = events.map(e => {
        const sev = (e.severity || 'MEDIUM').toUpperCase();
        const sevCls = sev === 'CRITICAL' ? 'bg-danger'
                    : sev === 'HIGH'     ? 'bg-orange'
                    : 'bg-warning text-dark';
        return `
        <div class="mitre-recent-item" style="color:#e6edf3">
          <span class="ts" style="color:#e6edf3">${(e.timestamp||'').split(' ')[1] || e.timestamp}</span>
          <span class="badge bg-danger font-monospace">${e.technique_id}</span>
          <span class="badge ${sevCls}" style="font-size:9px">${sev}</span>
          <span class="tactic" style="color:#e6edf3">${e.tactic_ko || e.tactic_id}</span>
          <span class="desc" style="color:#e6edf3">${escapeHtml(e.description||'')}</span>
        </div>`;
      }).join('');
    });
}

socket.on('mitre_hit', entry => {
  // MITRE 매핑 KPI
  const kpiEl = document.getElementById('kpi-mitre');
  if (kpiEl) kpiEl.textContent = parseInt(kpiEl.textContent || 0) + 1;

  // 매트릭스 셀 카운트 즉시 업데이트
  const cell = document.querySelector(
    `.mitre-technique[data-tactic="${entry.tactic_id}"][data-technique="${entry.technique_id}"]`
  );
  if (cell) {
    let cntEl = cell.querySelector('.tech-count');
    const cur = cntEl ? parseInt(cntEl.textContent, 10) : 0;
    const next = cur + 1;
    if (!cntEl) {
      cntEl = document.createElement('div');
      cntEl.className = 'tech-count';
      cell.appendChild(cntEl);
    }
    cntEl.textContent = next;
    cell.classList.remove('hit-low', 'hit-med', 'hit-high');
    cell.classList.add(next >= 10 ? 'hit-high' : next >= 3 ? 'hit-med' : 'hit-low');
    cell.classList.add('hit-flash');
    setTimeout(() => cell.classList.remove('hit-flash'), 800);
  }

  // 총합 카운트 업데이트
  const totalEl = document.getElementById('mitre-total');
  if (totalEl) totalEl.textContent = (parseInt(totalEl.textContent.replace(/,/g, '')) + 1).toLocaleString();

  // 최근 이벤트 프리펜드
  const recentList = document.getElementById('mitre-recent-list');
  if (recentList && recentList.querySelector('.mitre-recent-item')) {
    const sev = (entry.severity || 'MEDIUM').toUpperCase();
    const sevCls = sev === 'CRITICAL' ? 'bg-danger'
                : sev === 'HIGH'     ? 'bg-orange'
                : 'bg-warning text-dark';
    const div = document.createElement('div');
    div.className = 'mitre-recent-item new';
    div.setAttribute('style', 'color:#e6edf3');
    div.innerHTML = `
      <span class="ts" style="color:#e6edf3">${(entry.timestamp||'').split(' ')[1] || entry.timestamp}</span>
      <span class="badge bg-danger font-monospace">${entry.technique_id}</span>
      <span class="badge ${sevCls}" style="font-size:9px">${sev}</span>
      <span class="tactic" style="color:#e6edf3">${entry.tactic_ko || entry.tactic_id}</span>
      <span class="desc" style="color:#e6edf3">${escapeHtml(entry.description||'')}</span>`;
    recentList.insertBefore(div, recentList.firstChild);
    while (recentList.children.length > 30) recentList.removeChild(recentList.lastChild);
  }

  // 상세 로그 테이블 프리펜드
  mitreLogBuffer.unshift(entry);
  while (mitreLogBuffer.length > MITRE_LOG_MAX) mitreLogBuffer.pop();
  const logTbody = document.getElementById('mitre-log-tbody');
  if (logTbody) {
    renderMitreLog();
    const firstRow = logTbody.querySelector('tr');
    if (firstRow) {
      firstRow.classList.add('row-flash');
      setTimeout(() => firstRow.classList.remove('row-flash'), 800);
    }
  }
});

/* ════════════════════ 위협 인텔리전스 ════════════════════ */
function loadThreatIntel() {
  fetch('/api/threat-intel/status')
    .then(r => r.json())
    .then(d => renderThreatIntel(d))
    .catch(() => {});
}

function renderThreatIntel(d) {
  const stats = d.stats || {};
  const setIf = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  setIf('ti-bad-ip',      (stats.bad_ip_count||0).toLocaleString());
  setIf('ti-bad-url',     (stats.bad_url_count||0).toLocaleString());
  setIf('ti-total-match', (stats.total_matches||0).toLocaleString());
  setIf('ti-last-refresh', stats.last_refresh || '-');
  setIf('ov-ti-bad-ip',   (stats.bad_ip_count||0).toLocaleString());
  setIf('ov-ti-bad-url',  (stats.bad_url_count||0).toLocaleString());
  setIf('ov-ti-match',    (stats.total_matches||0).toLocaleString());

  const srcTbody = document.getElementById('ti-sources-tbody');
  if (srcTbody) {
    const rows = (d.sources || []).map(s => {
      const okCls = /ok/i.test(s.status) ? 'text-success' : 'text-danger';
      return `<tr style="color:#e6edf3">
        <td class="small" style="color:#e6edf3">${escapeHtml(s.name)}</td>
        <td class="small" style="color:#e6edf3">${s.type}</td>
        <td class="small font-monospace text-end" style="color:#e6edf3">${(s.count||0).toLocaleString()}</td>
        <td class="small ${okCls}">${escapeHtml(s.status||'-')}</td>
      </tr>`;
    }).join('');
    srcTbody.innerHTML = rows || '<tr><td colspan="4" class="text-center" style="color:#e6edf3">피드 로딩 중...</td></tr>';
  }

  const ipBox = document.getElementById('ti-sample-ips');
  if (ipBox) {
    const ips = d.sample_bad_ips || [];
    ipBox.innerHTML = ips.length
      ? ips.map(ip => `<div class="p-1 border-bottom border-secondary">${escapeHtml(ip)}</div>`).join('')
      : '<div class="text-muted p-2">샘플 없음</div>';
  }
  const urlBox = document.getElementById('ti-sample-urls');
  if (urlBox) {
    const urls = d.sample_bad_urls || [];
    urlBox.innerHTML = urls.length
      ? urls.map(u => `<div class="p-1 border-bottom border-secondary">${escapeHtml(u)}</div>`).join('')
      : '<div class="text-muted p-2">샘플 없음</div>';
  }

  // 매칭 리스트
  renderTiMatches(d.matches || []);

  svgDonut('ti-donut', [
    { label: '악성 IP', value: stats.bad_ip_count || 0, color: '#f85149' },
    { label: '악성 URL', value: stats.bad_url_count || 0, color: '#f0a500' },
  ], ((stats.bad_ip_count || 0) + (stats.bad_url_count || 0)).toLocaleString(), '총 IoC');
  svgHBars('ti-bars', (d.sources || []).slice(0, 6).map(s => ({
    label: s.name, value: s.count || 0, color: /ok/i.test(s.status || '') ? '#39d0d8' : '#8b949e',
  })), '개');
}

function renderTiMatches(matches) {
  const list = document.getElementById('ti-match-list');
  const ovList = document.getElementById('ov-ti-recent');
  const html = matches.length
    ? matches.map(tiMatchHtml).join('')
    : '<div class="text-muted text-center p-3">매칭 대기 중...</div>';
  if (list) list.innerHTML = html;
  if (ovList) ovList.innerHTML = matches.length
    ? matches.slice(0, 6).map(tiMatchHtml).join('')
    : '<div class="text-muted p-2">매칭 대기 중...</div>';
}

function tiMatchHtml(m) {
  const kindCls = m.kind === 'ip' ? 'bg-danger' : 'bg-orange';
  const dirIcon = m.direction === 'inbound' ? 'fa-arrow-down' : 'fa-arrow-up';
  const time = (m.timestamp || '').split(' ')[1] || m.timestamp || '';
  return `<div class="ti-match-item p-2 border-bottom border-secondary" style="color:#e6edf3">
    <div class="d-flex align-items-center gap-2 mb-1">
      <span class="badge ${kindCls}" style="font-size:9px">${(m.kind||'').toUpperCase()}</span>
      <span class="badge bg-danger" style="font-size:9px">CRITICAL</span>
      <i class="fa ${dirIcon} text-muted small"></i>
      <span class="text-muted small">${time}</span>
    </div>
    <div class="small font-monospace">${escapeHtml(m.indicator || '')}</div>
    <div class="small text-muted">
      ${m.local_ip ? `내부: ${escapeHtml(m.local_ip)}` : ''} ${m.port ? `· 포트 ${m.port}` : ''}
    </div>
    <div class="small">${escapeHtml(m.description || '')}</div>
  </div>`;
}

function refreshThreatIntel() {
  fetch('/api/threat-intel/refresh', { method: 'POST' })
    .then(r => r.json())
    .then(() => {
      setTimeout(loadThreatIntel, 1500);
    });
}

function checkThreatIntel() {
  const ip  = document.getElementById('ti-check-ip').value.trim();
  const url = document.getElementById('ti-check-url').value.trim();
  if (!ip && !url) return;
  fetch('/api/threat-intel/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, url }),
  })
    .then(r => r.json())
    .then(d => {
      const box = document.getElementById('ti-check-result');
      if (!box) return;
      const ipMsg = d.ip ? (d.ip_malicious
          ? `<span class="badge bg-danger">악성</span> ${d.ip}`
          : `<span class="badge bg-success">정상</span> ${d.ip}`)
        : '';
      const urlMsg = d.url ? (d.url_malicious
          ? `<span class="badge bg-danger">악성</span> ${escapeHtml(d.url)}`
          : `<span class="badge bg-success">정상</span> ${escapeHtml(d.url)}`)
        : '';
      box.innerHTML = [ipMsg, urlMsg].filter(Boolean).join('<br/>');
    });
}

const tiMatchCache = [];
function bumpTiSidebar(n) {
  const badge = document.getElementById('sidebar-ti-count');
  if (!badge) return;
  const cur = parseInt(badge.textContent || '0', 10) || 0;
  badge.textContent = (cur + n).toLocaleString();
}

socket.on('ti_match', m => {
  tiMatchCache.unshift(m);
  while (tiMatchCache.length > 60) tiMatchCache.pop();
  renderTiMatches(tiMatchCache);
  const totalEl = document.getElementById('ti-total-match');
  if (totalEl) totalEl.textContent = (parseInt(totalEl.textContent.replace(/,/g, '')) + 1).toLocaleString();
  const ovTotal = document.getElementById('ov-ti-match');
  if (ovTotal) ovTotal.textContent = (parseInt(ovTotal.textContent.replace(/,/g, '')) + 1).toLocaleString();
  bumpTiSidebar(1);
  pushLive('ti', 'high',
    `<b>IoC 매칭</b> <span class="lv-ip">${escapeHtml(m.indicator || '')}</span> ` +
    `<span class="text-muted">${escapeHtml(m.description || '')}</span>`);
});

socket.on('ti_feed_update', d => {
  renderThreatIntel(d);
});

/* ════════════════════ SIEM (외부 접근 로그) ════════════════════ */
let siemEventsBuffer = [];

function loadSiem() {
  fetch('/api/integrations/siem')
    .then(r => r.json())
    .then(renderSiemStatus)
    .catch(() => {});
}

function renderSiemStatus(d) {
  const stats = d.stats || {};
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (v ?? 0).toLocaleString();
  };
  set('siem-total', stats.total_events);
  set('siem-suspicious', stats.suspicious_events);
  set('siem-unique-ips', stats.unique_ips);
  set('siem-sources-ok', stats.sources_ok);
  const badge = document.getElementById('sidebar-siem-count');
  if (badge) badge.textContent = (stats.suspicious_events || 0).toLocaleString();
  setPipe('pipe-siem-total', stats.total_events);
  setPipe('pipe-siem-susp', stats.suspicious_events);

  const srcTbody = document.getElementById('siem-sources-tbody');
  if (srcTbody) {
    const rows = (d.sources || []).map(s => `
      <tr>
        <td class="small" title="${escapeHtml(s.path || '')}" style="color:#e6edf3">${escapeHtml(s.name)}</td>
        <td class="small" style="color:#e6edf3">${(s.events || 0).toLocaleString()}</td>
        <td class="small text-danger">${(s.suspicious || 0).toLocaleString()}</td>
        <td class="small">${s.exists
          ? '<span class="badge bg-success">연결됨</span>'
          : '<span class="badge bg-secondary">파일 없음</span>'}</td>
      </tr>`).join('');
    srcTbody.innerHTML = rows || '<tr><td colspan="4" class="text-muted text-center">소스 없음</td></tr>';
  }

  const topBox = document.getElementById('siem-top-ips');
  if (topBox) {
    const top = stats.top_ips || [];
    topBox.innerHTML = top.length
      ? top.map(([ip, cnt], i) => `
          <div class="d-flex justify-content-between p-1 border-bottom border-secondary small">
            <span class="font-monospace" style="color:#e6edf3">${i + 1}. ${escapeHtml(ip)}</span>
            <span class="text-warning">${cnt.toLocaleString()}건</span>
          </div>`).join('')
      : '<div class="text-muted p-2">데이터 없음</div>';
  }

  siemEventsBuffer = d.events || [];
  renderSiemEvents();

  const total = stats.total_events || 0, susp = stats.suspicious_events || 0;
  svgDonut('siem-donut', [
    { label: '정상 요청', value: Math.max(0, total - susp), color: '#3fb950' },
    { label: '의심 요청', value: susp, color: '#f85149' },
  ], total.toLocaleString(), '총 이벤트');
  svgHBars('siem-bars', (d.sources || []).slice(0, 6).map(s => ({
    label: s.name, value: s.events || 0, color: (s.suspicious || 0) > 0 ? '#f0a500' : '#39d0d8',
  })), '건');
}

function siemEventRow(e) {
  const sevCls = e.severity === 'CRITICAL' ? 'bg-danger'
              : e.severity === 'HIGH'     ? 'bg-orange'
              : e.severity === 'MEDIUM'   ? 'bg-warning text-dark'
              : 'bg-secondary';
  return `
    <tr ${e.suspicious ? 'style="background:rgba(248,81,73,.08)"' : ''}>
      <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.timestamp)}</td>
      <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.source)}</td>
      <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.ip)}</td>
      <td class="small font-monospace text-truncate" style="max-width:280px;color:#e6edf3"
          title="${escapeHtml(e.request)}">${escapeHtml(e.request)}</td>
      <td class="small ${e.status >= 400 ? 'text-danger' : 'text-success'}">${e.status}</td>
      <td class="small"><span class="badge ${sevCls}" style="font-size:9px">${escapeHtml(e.category)}</span></td>
    </tr>`;
}

function renderSiemEvents() {
  const tbody = document.getElementById('siem-events-tbody');
  if (!tbody) return;
  const suspiciousOnly = document.getElementById('siem-suspicious-only')?.checked;
  const rows = siemEventsBuffer
    .filter(e => !suspiciousOnly || e.suspicious)
    .slice(0, 200);
  tbody.innerHTML = rows.length
    ? rows.map(siemEventRow).join('')
    : '<tr><td colspan="6" class="text-muted text-center p-3">이벤트 없음</td></tr>';
}

socket.on('siem_event', e => {
  siemEventsBuffer.unshift(e);
  while (siemEventsBuffer.length > 500) siemEventsBuffer.pop();
  const bump = (id, n) => {
    const el = document.getElementById(id);
    if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g, '')) || 0) + n).toLocaleString();
  };
  bump('siem-total', 1);
  bump('pipe-siem-total', 1);
  if (e.suspicious) {
    bump('siem-suspicious', 1);
    bump('sidebar-siem-count', 1);
    bump('pipe-siem-susp', 1);
    // 의심 이벤트만 라이브 스트림에 노출 (정상 요청 노이즈 차단)
    pushLive('siem', e.severity,
      `<b>${escapeHtml(e.category)}</b> <span class="lv-ip">${escapeHtml(e.ip)}</span> ` +
      `<span class="text-muted">(${escapeHtml(e.source)})</span>`);
  }
  if (!document.getElementById('panel-siem').classList.contains('d-none')) {
    renderSiemEvents();
  }
});

socket.on('siem_status', renderSiemStatus);

/* ════════════════════ SSH 인증 로그 ════════════════════ */
let authEventsBuffer = [];

const AUTH_TYPE_META = {
  failed:   { badge: 'bg-danger',            label: '실패' },
  invalid:  { badge: 'bg-orange',            label: '무효계정' },
  preauth:  { badge: 'bg-warning text-dark', label: '조기종료' },
  accepted: { badge: 'bg-success',           label: '성공' },
};

function loadAuthlog() {
  fetch('/api/authlog').then(r => r.json()).then(renderAuthlog).catch(() => {});
}

function renderAuthlog(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('auth-total', stats.total);
  set('auth-failed', stats.failed);
  set('auth-invalid', stats.invalid);
  set('auth-accepted', stats.accepted);
  set('auth-brute', stats.brute_alerts);

  const modeBadge = document.getElementById('authlog-mode-badge');
  const modeNote = document.getElementById('authlog-mode-note');
  if (modeBadge) {
    const real = stats.mode === 'real';
    modeBadge.textContent = real ? '실시간 (auth.log)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
    modeBadge.style.background = real ? 'var(--green)' : '#30363d';
    modeBadge.style.color = real ? '#001417' : '#e6edf3';
  }
  if (modeNote) modeNote.textContent = stats.mode === 'demo'
    ? '(현재 데모 데이터 — 실서버에선 실제 auth.log를 읽습니다)' : '';

  const topBox = document.getElementById('auth-top-ips');
  if (topBox) {
    const top = stats.top_ips || [];
    topBox.innerHTML = top.length
      ? top.map(([ip, cnt], i) => `
          <div class="d-flex justify-content-between p-1 border-bottom border-secondary small">
            <span class="font-monospace" style="color:#e6edf3">${i + 1}. ${escapeHtml(ip)}</span>
            <span class="text-warning">${cnt.toLocaleString()}회</span>
          </div>`).join('')
      : '<div class="text-muted p-2">데이터 없음</div>';
  }

  authEventsBuffer = d.events || [];
  renderAuthEvents();

  svgDonut('auth-donut', [
    { label: '성공', value: stats.accepted || 0, color: '#3fb950' },
    { label: '실패', value: stats.failed || 0, color: '#f85149' },
    { label: '무효 계정', value: stats.invalid || 0, color: '#f0a500' },
  ], (stats.total || 0).toLocaleString(), '총 시도');
}

function authEventRow(e) {
  const meta = AUTH_TYPE_META[e.type] || { badge: 'bg-secondary', label: e.type };
  return `
    <tr ${e.type !== 'accepted' ? 'style="background:rgba(248,81,73,.06)"' : ''}>
      <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml(e.timestamp)}</td>
      <td class="small"><span class="badge ${meta.badge}" style="font-size:9px">${meta.label}</span></td>
      <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.user || '-')}</td>
      <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(e.ip)}</td>
      <td class="small" style="color:#e6edf3">${e.port || '-'}</td>
    </tr>`;
}

function renderAuthEvents() {
  const tbody = document.getElementById('auth-events-tbody');
  if (!tbody) return;
  const failOnly = document.getElementById('auth-fail-only')?.checked;
  const rows = authEventsBuffer.filter(e => !failOnly || e.type !== 'accepted').slice(0, 200);
  tbody.innerHTML = rows.length
    ? rows.map(authEventRow).join('')
    : '<tr><td colspan="5" class="text-muted text-center p-3">이벤트 없음</td></tr>';
}

socket.on('auth_event', e => {
  authEventsBuffer.unshift(e);
  while (authEventsBuffer.length > 500) authEventsBuffer.pop();
  const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
  bump('auth-total', 1);
  if (e.type === 'accepted') bump('auth-accepted', 1);
  else if (e.type === 'invalid') bump('auth-invalid', 1);
  else bump('auth-failed', 1);
  // 실패/무효/성공 모두 통합 라이브 스트림에 (성공은 info)
  const sev = e.type === 'accepted' ? 'info' : 'medium';
  const label = (AUTH_TYPE_META[e.type] || {}).label || e.type;
  pushLive('auth', sev,
    `<b>SSH ${escapeHtml(label)}</b> 계정 ${escapeHtml(e.user || '-')} ` +
    `<span class="lv-ip">${escapeHtml(e.ip)}</span>`);
  // 사이드바 배지: 실패/무효 누적
  if (e.type !== 'accepted') {
    const badge = document.getElementById('sidebar-auth-count');
    if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
  }
  if (!document.getElementById('panel-authlog')?.classList.contains('d-none')) {
    renderAuthEvents();
  }
});

/* ════════════════════ IP 평판 (AbuseIPDB) ════════════════════ */
let repEventsBuffer = [];
let repMinScore = 75;

function loadReputation() {
  fetch('/api/integrations/abuseipdb').then(r => r.json()).then(renderReputation).catch(() => {});
}

function repScoreBadge(score) {
  score = score || 0;
  let cls = 'bg-success', txt = '#001417';
  if (score >= repMinScore) { cls = 'bg-danger'; txt = '#fff'; }
  else if (score >= 25) { cls = 'bg-warning'; txt = '#1a1a1a'; }
  return `<span class="badge ${cls}" style="color:${txt};font-size:10px">${score}/100</span>`;
}

function renderReputation(d) {
  const stats = d.stats || {};
  repMinScore = d.min_score || 75;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('rep-total', stats.total_checks);
  set('rep-malicious', stats.malicious);
  set('rep-api-calls', stats.api_calls);
  set('rep-cache-hits', stats.cache_hits);
  set('rep-cache-size', d.cache_size);
  const minEl = document.getElementById('rep-min-score');
  if (minEl) minEl.textContent = repMinScore;

  const badge = document.getElementById('rep-mode-badge');
  const note = document.getElementById('rep-mode-note');
  if (badge) {
    const real = stats.mode === 'abuseipdb';
    badge.textContent = real ? '실조회 (AbuseIPDB)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
    badge.style.background = real ? 'var(--green)' : '#30363d';
    badge.style.color = real ? '#001417' : '#e6edf3';
  }
  if (note) note.textContent = stats.mode === 'demo'
    ? '(API 키 없음 — 데모 점수. .env ABUSEIPDB_API_KEY 설정 시 실조회)' : '';

  repEventsBuffer = d.recent || [];
  renderRepEvents();

  const buckets = [0, 0, 0, 0];
  (d.recent || []).forEach(r => {
    const s = r.score || 0;
    buckets[s >= 75 ? 3 : s >= 50 ? 2 : s >= 25 ? 1 : 0]++;
  });
  svgHBars('rep-bars', [
    { label: '악성 75+', value: buckets[3], color: '#f85149' },
    { label: '주의 50-74', value: buckets[2], color: '#f0a500' },
    { label: '낮음 25-49', value: buckets[1], color: '#d29922' },
    { label: '양호 0-24', value: buckets[0], color: '#3fb950' },
  ], '개');
}

function repRow(r) {
  const src = r.source === 'abuseipdb' ? 'AbuseIPDB' : (r.source === 'demo' ? '데모' : r.source);
  return `
    <tr ${(r.score || 0) >= repMinScore ? 'style="background:rgba(248,81,73,.08)"' : ''}>
      <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((r.checked_at || '').slice(11))}</td>
      <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(r.ip)}</td>
      <td>${repScoreBadge(r.score)}</td>
      <td class="small" style="color:#e6edf3">${(r.total_reports || 0).toLocaleString()}</td>
      <td class="small" style="color:#e6edf3">${escapeHtml(r.country || '-')}</td>
      <td class="small text-muted">${escapeHtml(src)}</td>
    </tr>`;
}

function renderRepEvents() {
  const tbody = document.getElementById('rep-events-tbody');
  if (!tbody) return;
  tbody.innerHTML = repEventsBuffer.length
    ? repEventsBuffer.slice(0, 100).map(repRow).join('')
    : '<tr><td colspan="6" class="text-muted text-center p-3">아직 조회한 외부 IP가 없습니다</td></tr>';
}

function checkReputation() {
  const inp = document.getElementById('rep-check-input');
  const box = document.getElementById('rep-check-result');
  const ip = (inp?.value || '').trim();
  if (!ip) return;
  if (box) box.innerHTML = '<span class="text-muted">조회 중...</span>';
  fetch('/api/reputation/check', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  }).then(r => r.json()).then(r => {
    if (!box) return;
    if (r.error) { box.innerHTML = `<span class="text-danger">${escapeHtml(r.error)}</span>`; return; }
    if (r.source === 'internal') {
      box.innerHTML = `<span class="text-info">${escapeHtml(r.ip)} — 내부/Tailscale IP (조회 제외)</span>`;
      return;
    }
    const mal = (r.score || 0) >= repMinScore;
    box.innerHTML = `
      <div class="p-1">
        <div class="mb-1">${repScoreBadge(r.score)} <b class="font-monospace ms-1">${escapeHtml(r.ip)}</b>
          ${mal ? '<span class="text-danger ms-1">악성</span>' : '<span class="text-success ms-1">양호</span>'}</div>
        <div class="small text-muted">신고 ${(r.total_reports||0).toLocaleString()}건 · 국가 ${escapeHtml(r.country||'?')}
          · ISP ${escapeHtml(r.isp||'?')}</div>
        <div class="small text-muted">${escapeHtml(r.usage_type||'')}${r.last_reported ? ' · 최근신고 '+escapeHtml(r.last_reported.slice(0,10)) : ''}</div>
      </div>`;
    // 조회 결과를 최근 목록/스트림에도 반영
    repEventsBuffer.unshift(r);
    renderRepEvents();
  }).catch(() => { if (box) box.innerHTML = '<span class="text-danger">조회 실패</span>'; });
}

socket.on('ip_reputation', r => {
  if (!r || r.source === 'internal') return;
  repEventsBuffer.unshift(r);
  while (repEventsBuffer.length > 100) repEventsBuffer.pop();
  const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
  bump('rep-total', 1);
  if ((r.score || 0) >= repMinScore) {
    bump('rep-malicious', 1);
    const rbadge = document.getElementById('sidebar-rep-count');
    if (rbadge) rbadge.textContent = ((parseInt(rbadge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
    pushLive('rep', 'high',
      `<b>악성 IP 평판</b> <span class="lv-ip">${escapeHtml(r.ip)}</span> ` +
      `신뢰점수 ${r.score}/100 · 신고 ${(r.total_reports||0).toLocaleString()}건`);
  }
  if (!document.getElementById('panel-reputation')?.classList.contains('d-none')) {
    renderRepEvents();
  }
});

/* ════════════════════ EDR (AI 엔드포인트) ════════════════════ */
let edrDetBuffer = [];

function sevColor(sev) {
  return { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow, #d29922)', LOW: '#8b949e' }[sev] || '#8b949e';
}
function riskBadge(risk) {
  risk = risk || 0;
  let cls = 'bg-success', txt = '#001417';
  if (risk >= 70) { cls = 'bg-danger'; txt = '#fff'; }
  else if (risk >= 40) { cls = 'bg-warning'; txt = '#1a1a1a'; }
  return `<span class="badge ${cls}" style="color:${txt};font-size:10px">${risk}</span>`;
}

function loadEdr() {
  fetch('/api/integrations/edr').then(r => r.json()).then(renderEdr).catch(() => {});
}

function renderEdr(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('edr-proc-count', stats.process_count);
  set('edr-critical', stats.critical);
  set('edr-high', stats.high);
  set('edr-detections', stats.detections);
  set('edr-responses', stats.responses);
  const hostEl = document.getElementById('edr-host');
  if (hostEl) hostEl.textContent = d.host || '-';

  const badge = document.getElementById('edr-mode-badge');
  const note = document.getElementById('edr-mode-note');
  if (badge) {
    const real = stats.mode === 'real';
    badge.textContent = real ? '실센서 (psutil)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
    badge.style.background = real ? 'var(--green)' : '#30363d';
    badge.style.color = real ? '#001417' : '#e6edf3';
  }
  if (note) note.textContent = stats.mode === 'demo'
    ? '(현재 데모 프로세스 — 실서버에선 실제 실행 프로세스를 감시합니다)' : '';

  edrDetBuffer = d.detections || [];
  renderEdrDetections();
  drawEdrFlow(d);

  const ptb = document.getElementById('edr-proc-tbody');
  if (ptb) {
    const procs = (d.processes || []).filter(p => (p.risk || 0) > 0).slice(0, 40);
    ptb.innerHTML = procs.length
      ? procs.map(p => `
        <tr>
          <td>${riskBadge(p.risk)}</td>
          <td class="small font-monospace" style="color:#e6edf3">${p.pid}</td>
          <td class="small" style="color:#e6edf3" title="${escapeHtml(p.cmdline || '')}">${escapeHtml(p.name)}</td>
          <td class="small text-muted">${escapeHtml(p.user || '-')}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="text-muted text-center p-3">위험 프로세스 없음 (정상)</td></tr>';
  }
}

// Falcon 스타일 프로세스 공격 흐름도 (SVG) — 부모→프로세스→IOA 체인
function drawEdrFlow(d) {
  const svg = document.getElementById('edr-flow');
  if (!svg) return;
  const dets = (d.detections || []).slice(0, 5);
  const W = svg.clientWidth || 640;
  const rowH = 54, topPad = 12;
  const H = Math.max(120, topPad * 2 + dets.length * rowH);
  svg.setAttribute('height', H);

  if (!dets.length) {
    svg.innerHTML = `<text x="${W / 2}" y="60" text-anchor="middle" font-size="12" fill="#8b949e">탐지된 위협 프로세스가 없습니다 (정상)</text>`;
    return;
  }

  const riskColor = r => r >= 70 ? '#f85149' : (r >= 40 ? '#f0a500' : '#8b949e');
  const bw = 150, bh = 34, x0 = 8, x1 = x0 + bw + 60, x2 = x1 + bw + 60;

  const box = (x, y, w, title, sub, col) => `
    <rect x="${x}" y="${y}" width="${w}" height="${bh}" rx="7" fill="#0d1117" stroke="${col}" stroke-width="1.8"/>
    <text x="${x + 9}" y="${y + 14}" font-size="11" font-weight="700" fill="#e6edf3">${escapeHtml((title || '').slice(0, 22))}</text>
    <text x="${x + 9}" y="${y + 27}" font-size="9" font-family="monospace" fill="#8b949e">${escapeHtml((sub || '').slice(0, 26))}</text>`;
  const arrow = (xa, xb, y) => `<line x1="${xa}" y1="${y}" x2="${xb}" y2="${y}" stroke="#484f58" stroke-width="2" marker-end="url(#edr-arw)"/>`;

  let rows = '';
  dets.forEach((det, i) => {
    const y = topPad + i * rowH;
    const yc = y + bh / 2;
    const col = riskColor(det.risk);
    rows += box(x0, y, bw, det.parent || '?', '부모 프로세스', '#484f58');
    rows += arrow(x0 + bw, x1, yc);
    rows += box(x1, y, bw, `${det.process} (${det.pid})`, det.cmdline || '', col);
    rows += arrow(x1 + bw, x2, yc);
    // IOA/severity 노드
    rows += `<rect x="${x2}" y="${y}" width="${bw}" height="${bh}" rx="7" fill="${col}22" stroke="${col}" stroke-width="1.8"/>
      <text x="${x2 + 9}" y="${y + 14}" font-size="10.5" font-weight="700" fill="${col}">${escapeHtml(det.severity)} · 위험 ${det.risk}</text>
      <text x="${x2 + 9}" y="${y + 27}" font-size="9" fill="#c9d1d9">${escapeHtml((det.mitre || '') + ' ' + (det.rule || '').replace('IOA-', ''))}</text>`;
  });
  svg.innerHTML = `<defs><marker id="edr-arw" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#484f58"/></marker></defs>${rows}`;
}

function edrDetRow(det) {
  return `
    <tr style="background:rgba(248,81,73,${det.severity === 'CRITICAL' ? '.10' : '.05'})">
      <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((det.timestamp || '').slice(11))}</td>
      <td>${riskBadge(det.risk)}</td>
      <td class="small" style="color:#e6edf3" title="${escapeHtml(det.cmdline || '')}">
        <span class="font-monospace">${escapeHtml(det.process)}</span>
        <span class="text-muted">(${det.pid})</span></td>
      <td class="small" style="color:${sevColor(det.severity)}">${escapeHtml(det.description)}</td>
      <td class="small"><span class="badge bg-dark">${escapeHtml(det.mitre || '-')}</span></td>
      <td><button class="btn btn-xs btn-outline-danger" onclick="edrKill(${det.pid})" title="프로세스 격리">
        <i class="fa fa-ban"></i></button></td>
    </tr>`;
}

function renderEdrDetections() {
  const tbody = document.getElementById('edr-detections-tbody');
  if (!tbody) return;
  tbody.innerHTML = edrDetBuffer.length
    ? edrDetBuffer.slice(0, 60).map(edrDetRow).join('')
    : '<tr><td colspan="6" class="text-muted text-center p-3">탐지된 위협 없음</td></tr>';
}

function edrKill(pid) {
  if (!confirm(`PID ${pid} 프로세스를 격리(종료)할까요?\n(simulate 모드면 기록만, 시스템/대시보드 프로세스는 안전장치로 보호)`)) return;
  fetch('/api/edr/kill', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pid })
  }).then(r => r.json()).then(r => {
    alert(r.ok ? `대응 완료: ${r.detail}` : `대응 보류: ${r.detail}`);
  }).catch(() => alert('대응 요청 실패'));
}

socket.on('edr_detection', det => {
  edrDetBuffer.unshift(det);
  while (edrDetBuffer.length > 300) edrDetBuffer.pop();
  const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
  bump('edr-detections', 1);
  if (det.severity === 'CRITICAL') bump('edr-critical', 1);
  else if (det.severity === 'HIGH') bump('edr-high', 1);
  const badge = document.getElementById('sidebar-edr-count');
  if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
  pushLive('edr', (det.severity || 'high').toLowerCase(),
    `<b>EDR ${escapeHtml(det.description)}</b> ` +
    `<span class="font-monospace">${escapeHtml(det.process)}(${det.pid})</span> · 위험 ${det.risk}`);
  if (!document.getElementById('panel-edr')?.classList.contains('d-none')) {
    renderEdrDetections();
    drawEdrFlow({ detections: edrDetBuffer });
  }
});

socket.on('edr_status', s => {
  if (document.getElementById('panel-edr')?.classList.contains('d-none')) return;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('edr-proc-count', (s.stats || {}).process_count);
});

/* ════════════════════ 네트워크 관제 ════════════════════ */
function loadNetwork() {
  fetch('/api/integrations/network').then(r => r.json()).then(renderNetwork).catch(() => {});
}

function renderNetwork(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('net-established', stats.established);
  set('net-listening', stats.listening_ports);
  set('net-peers', stats.external_peers);
  set('net-malicious', stats.malicious_conns);
  set('net-bandwidth', Math.round((stats.down_bps || 0) / 1024));

  const badge = document.getElementById('net-mode-badge');
  const note = document.getElementById('net-mode-note');
  if (badge) {
    const real = stats.mode === 'real';
    badge.textContent = real ? '실측 (psutil)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
    badge.style.background = real ? 'var(--green)' : '#30363d';
    badge.style.color = real ? '#001417' : '#e6edf3';
  }
  if (note) note.textContent = stats.mode === 'demo'
    ? '(현재 데모 데이터 — 실서버에선 실제 연결/포트/대역폭을 읽습니다)' : '';

  renderNetTargets(d.targets || []);

  const ct = document.getElementById('net-conns-tbody');
  if (ct) {
    const conns = d.connections || [];
    ct.innerHTML = conns.length
      ? conns.map(c => `
        <tr ${c.external ? 'style="background:rgba(247,144,0,.06)"' : ''}>
          <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(c.laddr)}</td>
          <td class="small font-monospace" style="color:${c.external ? 'var(--orange)' : '#e6edf3'}">${escapeHtml(c.raddr)}</td>
          <td class="small text-muted">${escapeHtml(c.status)}</td>
          <td class="small" style="color:#e6edf3">${escapeHtml(c.proc || '?')}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="text-muted text-center p-3">연결 없음</td></tr>';
  }

  const lt = document.getElementById('net-listen-tbody');
  if (lt) {
    const ls = d.listening || [];
    lt.innerHTML = ls.length
      ? ls.map(l => `
        <tr>
          <td class="small font-monospace text-warning">${l.port}</td>
          <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(l.addr)}</td>
          <td class="small" style="color:#e6edf3">${escapeHtml(l.proc || '?')}</td>
        </tr>`).join('')
      : '<tr><td colspan="3" class="text-muted text-center p-3">없음</td></tr>';
  }

  renderNetEvents(d.events || []);
  drawNetTopology(d);
}

// NMS 스타일 네트워크 토폴로지 (SVG) — 중앙 호스트 + 방사형 피어 연결
function drawNetTopology(d) {
  const svg = document.getElementById('net-topology');
  if (!svg) return;
  const W = svg.clientWidth || 520, H = 360, cx = W / 2, cy = H / 2;
  const conns = d.connections || [];
  const listening = d.listening || [];
  const events = d.events || [];
  const badIps = new Set(events.filter(e => e.kind === 'MALICIOUS_CONN').map(e => (e.details || {}).rip).filter(Boolean));

  // 원격 피어 집계 (IP별)
  const peers = {};
  conns.forEach(c => {
    if (!c.rip || c.rip === '-') return;
    if (!peers[c.rip]) peers[c.rip] = { ip: c.rip, external: c.external, count: 0, procs: new Set() };
    peers[c.rip].count++;
    if (c.proc) peers[c.rip].procs.add(c.proc);
  });
  const peerList = Object.values(peers).slice(0, 14);

  const colorOf = p => badIps.has(p.ip) ? '#f85149' : (p.external ? '#f0a500' : '#3fb950');
  const R = Math.min(cx, cy) - 62;
  let edges = '', nodes = '';

  peerList.forEach((p, i) => {
    const ang = (2 * Math.PI * i) / Math.max(1, peerList.length) - Math.PI / 2;
    const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
    const col = colorOf(p), bad = badIps.has(p.ip);
    edges += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${col}" stroke-width="${bad ? 2.5 : 1.3}" stroke-opacity="${bad ? 0.9 : 0.45}" ${bad ? 'stroke-dasharray="4 3"' : ''}/>`;
    const r = 7 + Math.min(6, p.count);
    nodes += `<g>
      <circle cx="${x}" cy="${y}" r="${r}" fill="#0d1117" stroke="${col}" stroke-width="2"/>
      ${bad ? `<circle cx="${x}" cy="${y}" r="${r + 4}" fill="none" stroke="${col}" stroke-width="1" stroke-opacity="0.5"><animate attributeName="r" from="${r + 2}" to="${r + 9}" dur="1.2s" repeatCount="indefinite"/><animate attributeName="stroke-opacity" from="0.6" to="0" dur="1.2s" repeatCount="indefinite"/></circle>` : ''}
      <text x="${x}" y="${y - r - 5}" text-anchor="middle" font-size="10" font-family="monospace" fill="${col}">${escapeHtml(p.ip)}</text>
      <text x="${x}" y="${y + r + 12}" text-anchor="middle" font-size="9" fill="#8b949e">${[...p.procs][0] || ''} ×${p.count}</text>
    </g>`;
  });

  // 중앙 호스트 + 오픈 포트 링
  const portRing = listening.slice(0, 10).map((l, i) => {
    const ang = (2 * Math.PI * i) / Math.max(1, Math.min(10, listening.length));
    const x = cx + 34 * Math.cos(ang), y = cy + 34 * Math.sin(ang);
    const risky = ![22, 80, 443, 5055].includes(l.port);
    return `<circle cx="${x}" cy="${y}" r="3.5" fill="${risky ? '#f85149' : '#39d0d8'}"/>
      <text x="${x}" y="${y - 6}" text-anchor="middle" font-size="8" fill="${risky ? '#f85149' : '#8b949e'}">${l.port}</text>`;
  }).join('');

  const host = `<g>
    <circle cx="${cx}" cy="${cy}" r="26" fill="#161b22" stroke="var(--cyan,#39d0d8)" stroke-width="2.5"/>
    <text x="${cx}" y="${cy - 1}" text-anchor="middle" font-family="Font Awesome 6 Free" font-weight="900" font-size="18" fill="#39d0d8">&#xf233;</text>
    <text x="${cx}" y="${cy + 42}" text-anchor="middle" font-size="11" font-weight="700" fill="#e6edf3">홈서버</text>
  </g>`;

  const empty = peerList.length === 0 ? `<text x="${cx}" y="${cy + 70}" text-anchor="middle" font-size="11" fill="#8b949e">활성 외부 연결 없음</text>` : '';
  svg.innerHTML = edges + portRing + nodes + host + empty;
}

function renderNetTargets(targets) {
  const box = document.getElementById('net-targets');
  if (!box) return;
  box.innerHTML = targets.length
    ? targets.map(t => `
      <div class="p-2 border rounded" style="border-color:${t.up ? 'var(--green)' : 'var(--red)'}!important; min-width:160px; background:rgba(${t.up ? '63,185,80' : '248,81,73'},.08)">
        <div class="small" style="color:#e6edf3;font-weight:600">
          <i class="fa fa-circle me-1" style="font-size:8px;color:${t.up ? 'var(--green)' : 'var(--red)'}"></i>${escapeHtml(t.name)}</div>
        <div class="small font-monospace text-muted">${escapeHtml(t.host)}:${t.port}</div>
        <div class="small" style="color:${t.up ? 'var(--green)' : 'var(--red)'}">${t.up ? 'UP · ' + (t.latency_ms ?? '?') + 'ms' : 'DOWN'}</div>
      </div>`).join('')
    : '<div class="text-muted">감시 대상 없음</div>';
}

function renderNetEvents(events) {
  const box = document.getElementById('net-events');
  if (!box) return;
  box.innerHTML = events.length
    ? events.map(e => `
      <div class="p-1 border-bottom border-secondary small">
        <span class="badge" style="background:${sevColor(e.severity)};font-size:9px">${escapeHtml(e.severity)}</span>
        <span style="color:#e6edf3" class="ms-1">${escapeHtml(e.description)}</span>${demoBadge(e.details)}
        <div class="text-muted" style="font-size:10px">${escapeHtml(e.timestamp)}</div>
      </div>`).join('')
    : '<div class="text-muted p-2">이벤트 없음</div>';
}

socket.on('net_event', e => {
  const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
  if (e.kind === 'MALICIOUS_CONN') bump('net-malicious', 1);
  const badge = document.getElementById('sidebar-net-count');
  if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
  pushLive('net', (e.severity || 'medium').toLowerCase(), `<b>네트워크</b> ${escapeHtml(e.description)}${demoBadge(e.details)}`);
  if (!document.getElementById('panel-network')?.classList.contains('d-none')) loadNetwork();
});

socket.on('net_status', s => {
  if (document.getElementById('panel-network')?.classList.contains('d-none')) return;
  const stats = s.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('net-established', stats.established);
  set('net-bandwidth', Math.round((stats.down_bps || 0) / 1024));
  renderNetTargets(s.targets || []);
});

/* ════════════════════ 퍼플팀 검증 ════════════════════ */
let purpleScenarios = [];

function loadPurple() {
  fetch('/api/purple/status').then(r => r.json()).then(renderPurple).catch(() => {});
}

function runPurpleAll() {
  const btnRow = document.getElementById('purple-tbody');
  if (btnRow) btnRow.innerHTML = '<tr><td colspan="6" class="text-center p-3 text-purple"><i class="fa fa-spinner fa-spin me-2"></i>모의 공격 주입 & 탐지 검증 중...</td></tr>';
  fetch('/api/purple/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: 'all' }) })
    .then(r => r.json()).then(() => loadPurple()).catch(() => {});
}

function runPurpleOne(sid) {
  fetch('/api/purple/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: sid }) })
    .then(r => r.json()).then(() => loadPurple()).catch(() => {});
}

function renderPurple(d) {
  const stats = d.stats || {};
  purpleScenarios = d.scenarios || [];
  const passed = purpleScenarios.filter(s => s.result && s.result.detected).length;
  const ran = purpleScenarios.filter(s => s.result).length;
  const failed = ran - passed;
  const cov = stats.last_coverage;

  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('purple-coverage', cov == null ? '-' : cov + '%');
  set('purple-passed', ran ? passed : '-');
  set('purple-failed', ran ? failed : '-');
  set('purple-runs', (stats.runs || 0).toLocaleString());

  const badge = document.getElementById('purple-cov-badge');
  if (badge) {
    badge.textContent = '커버리지 ' + (cov == null ? '-' : cov + '%');
    const c = cov == null ? '#30363d' : (cov >= 90 ? 'var(--green)' : cov >= 60 ? 'var(--orange)' : 'var(--red)');
    badge.style.background = c;
    badge.style.color = (cov != null && cov >= 90) ? '#001417' : '#e6edf3';
  }
  const sb = document.getElementById('sidebar-purple-cov');
  if (sb) sb.textContent = cov == null ? '-' : cov + '%';

  const tb = document.getElementById('purple-tbody');
  if (tb) {
    tb.innerHTML = purpleScenarios.map(s => {
      const r = s.result;
      const verdict = !r ? '<span class="badge bg-secondary" style="font-size:10px">미실행</span>'
        : (r.detected ? '<span class="badge bg-success" style="font-size:10px">PASS</span>'
                      : '<span class="badge bg-danger" style="font-size:10px">FAIL</span>');
      return `<tr style="${r && !r.detected ? 'background:rgba(248,81,73,.08)' : ''}">
        <td>${verdict}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(s.name)}</td>
        <td><span class="badge bg-dark" style="font-size:9px">${escapeHtml(s.mitre)}</span></td>
        <td class="small text-muted">${escapeHtml(s.expect)}</td>
        <td class="small" style="color:#e6edf3">${r ? escapeHtml(r.detail) : '-'}</td>
        <td><button class="btn btn-xs btn-outline-purple" onclick="runPurpleOne('${s.id}')" title="이 시나리오만 실행"><i class="fa fa-play"></i></button></td>
      </tr>`;
    }).join('');
  }
  drawPurpleFlow(passed, ran, cov);
}

// 공격 → 탐지 파이프라인 흐름 시각화 (SVG)
function drawPurpleFlow(passed, ran, cov) {
  const svg = document.getElementById('purple-flow');
  if (!svg) return;
  const active = ran > 0;
  const okColor = cov != null && cov >= 90 ? '#3fb950' : (cov >= 60 ? '#f0a500' : '#f85149');
  const stages = [
    { icon: '', label: '모의 공격', sub: ran ? ran + '개 시나리오' : '대기', color: '#9d79f2' },
    { icon: '', label: '탐지 엔진', sub: 'Sigma·EDR·평판', color: active ? okColor : '#30363d' },
    { icon: '', label: 'AI 트리아지', sub: '정탐/오탐', color: active ? '#58a6ff' : '#30363d' },
    { icon: '', label: 'SOAR 대응', sub: '차단/종결', color: active ? '#39d0d8' : '#30363d' },
    { icon: '', label: '알림/인시던트', sub: '폰 푸시', color: active ? '#f0a500' : '#30363d' },
  ];
  const W = svg.clientWidth || 720, n = stages.length;
  const boxW = 118, gap = (W - boxW * n) / (n - 1), y = 30, h = 74;
  let parts = '';
  stages.forEach((s, i) => {
    const x = i * (boxW + gap);
    if (i < n - 1) {
      const ax = x + boxW, ax2 = x + boxW + gap;
      parts += `<line x1="${ax}" y1="${y + h / 2}" x2="${ax2}" y2="${y + h / 2}" stroke="${active ? okColor : '#30363d'}" stroke-width="2.5" marker-end="url(#pt-arrow)"/>`;
    }
    parts += `<g>
      <rect x="${x}" y="${y}" width="${boxW}" height="${h}" rx="9" fill="#0d1117" stroke="${s.color}" stroke-width="2"/>
      <text x="${x + boxW / 2}" y="${y + 26}" text-anchor="middle" font-family="Font Awesome 6 Free" font-weight="900" font-size="18" fill="${s.color}">${s.icon}</text>
      <text x="${x + boxW / 2}" y="${y + 46}" text-anchor="middle" font-size="12" font-weight="700" fill="#e6edf3">${s.label}</text>
      <text x="${x + boxW / 2}" y="${y + 62}" text-anchor="middle" font-size="10" fill="#8b949e">${s.sub}</text>
    </g>`;
  });
  const covText = cov == null ? '' :
    `<text x="${W / 2}" y="18" text-anchor="middle" font-size="12" font-weight="700" fill="${okColor}">탐지 커버리지 ${cov}% (${passed}/${ran} PASS)</text>`;
  svg.innerHTML = `<defs><marker id="pt-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="${active ? okColor : '#30363d'}"/></marker></defs>${covText}${parts}`;
}

socket.on('purple_run', () => {
  if (!document.getElementById('panel-purple')?.classList.contains('d-none')) loadPurple();
});

/* ════════════════════ 일일 AI 리포트 ════════════════════ */
function loadReport() {
  fetch('/api/report/status').then(r => r.json()).then(renderReportPanel).catch(() => {});
}

function reportKpiCards(hl) {
  const card = (label, val, color) =>
    `<div class="col-4 col-md-3"><div class="stat-card stat-sm" style="border-left:3px solid ${color}">
      <div class="stat-value" style="color:${color}">${(val ?? 0).toLocaleString()}</div>
      <div class="stat-label">${label}</div></div></div>`;
  return [
    card('총 알림', hl.alerts_total, 'var(--cyan)'),
    card('정탐', hl.true_positives, 'var(--orange)'),
    card('오탐', hl.false_positives, 'var(--green)'),
    card('오탐율 %', hl.fp_rate, '#8b949e'),
    card('자동 차단', hl.auto_blocked, 'var(--red)'),
    card('EDR', hl.edr_detections, 'var(--info,#58a6ff)'),
    card('Sigma', hl.sigma_matches, 'var(--purple)'),
    card('브루트포스', hl.brute_alerts, 'var(--orange)'),
  ].join('');
}

function showReport(rep) {
  if (!rep) return;
  const t = document.getElementById('report-title');
  if (t) t.textContent = `리포트 ${rep.id}`;
  const g = document.getElementById('report-generated');
  if (g) g.textContent = rep.generated + (rep.ai_mode === 'claude' ? ' · Claude' : ' · 규칙기반');
  const k = document.getElementById('report-kpis');
  if (k) k.innerHTML = reportKpiCards(rep.highlights || {});
  const b = document.getElementById('report-briefing');
  if (b) b.textContent = rep.briefing || '(브리핑 없음)';
}

function renderReportPanel(d) {
  const stats = d.stats || {};
  const badge = document.getElementById('report-mode-badge');
  if (badge) {
    const claude = stats.ai_mode === 'claude';
    badge.textContent = claude ? 'Claude 브리핑' : '규칙 기반 (API 키 없음)';
    badge.style.background = claude ? 'var(--green)' : '#30363d';
    badge.style.color = claude ? '#001417' : '#e6edf3';
  }
  const note = document.getElementById('report-mode-note');
  if (note) note.textContent = stats.ai_mode === 'claude' ? '' : '(ANTHROPIC_API_KEY 설정 시 Claude가 작성)';

  const hist = document.getElementById('report-history');
  if (hist) {
    const hs = d.history || [];
    hist.innerHTML = hs.length
      ? hs.map(h => `
        <div class="p-2 border-bottom border-secondary small" style="cursor:pointer" onclick="openReport('${h.id}')">
          <div style="color:#e6edf3;font-weight:600"><i class="fa fa-file-lines me-1 text-cyan"></i>${escapeHtml(h.generated)}</div>
          <div class="text-muted" style="font-size:11px">
            알림 ${h.highlights?.alerts_total ?? 0} · 정탐 ${h.highlights?.true_positives ?? 0} · 오탐 ${h.highlights?.false_positives ?? 0}
            ${h.trigger === 'scheduled' ? '· <span class="text-info">예약</span>' : ''}</div>
        </div>`).join('')
      : '<div class="text-muted p-2">리포트 없음 — "지금 생성"을 눌러보세요</div>';
  }
  if (d.latest) showReport(d.latest);
}

function openReport(rid) {
  fetch('/api/report/' + rid).then(r => r.json()).then(showReport).catch(() => {});
}

function generateReport() {
  const b = document.getElementById('report-briefing');
  if (b) b.textContent = 'AI가 브리핑을 작성 중입니다...';
  fetch('/api/report/generate', { method: 'POST' }).then(r => r.json()).then(rep => {
    showReport(rep);
    loadReport();
  }).catch(() => { if (b) b.textContent = '생성 실패'; });
}

socket.on('daily_report', () => {
  if (!document.getElementById('panel-report')?.classList.contains('d-none')) loadReport();
});

/* ════════════════════ Sigma 룰 엔진 ════════════════════ */
function loadSigma() {
  fetch('/api/integrations/sigma').then(r => r.json()).then(renderSigma).catch(() => {});
}
function reloadSigma() {
  fetch('/api/sigma/reload', { method: 'POST' }).then(r => r.json()).then(renderSigma).catch(() => {});
}

const SIGMA_LEVEL = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow,#d29922)', low: '#8b949e', informational: '#8b949e' };
function sigmaLevelBadge(lv) {
  return `<span class="badge" style="background:${SIGMA_LEVEL[lv] || '#555'};font-size:9px;color:#fff">${escapeHtml(lv || '?')}</span>`;
}

let sigmaMatchBuffer = [];

function renderSigma(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('sigma-rules', stats.rules_loaded);
  set('sigma-matches', stats.matches);
  set('sigma-evals', stats.evaluations);
  set('sigma-errors', stats.rules_error);

  const badge = document.getElementById('sigma-mode-badge');
  const note = document.getElementById('sigma-mode-note');
  if (badge) {
    const on = stats.enabled;
    badge.textContent = on ? `활성 · ${stats.rules_loaded}룰` : '비활성 (PyYAML 없음)';
    badge.style.background = on ? 'var(--green)' : '#30363d';
    badge.style.color = on ? '#001417' : '#e6edf3';
  }
  if (note) note.textContent = stats.enabled ? '' : '(PyYAML 미설치 — pip install pyyaml 후 재시작)';

  const rt = document.getElementById('sigma-rules-tbody');
  if (rt) {
    const rules = d.rules || [];
    rt.innerHTML = rules.length
      ? rules.map(r => `
        <tr style="opacity:${r.enabled ? 1 : 0.45}">
          <td>${sigmaLevelBadge(r.level)}</td>
          <td class="small" style="color:#e6edf3" title="${escapeHtml(r.id)}">${escapeHtml(r.title)}</td>
          <td class="small">${(r.mitre || []).map(m => `<span class="badge bg-dark" style="font-size:9px">${escapeHtml(m)}</span>`).join(' ') || '-'}</td>
          <td><div class="form-check form-switch mb-0">
            <input class="form-check-input" type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleSigma('${escapeHtml(r.id)}')">
          </div></td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="text-muted text-center p-3">룰 없음</td></tr>';
  }

  sigmaMatchBuffer = d.matches || [];
  renderSigmaMatches();

  const lc = {};
  (d.rules || []).forEach(r => { lc[r.level] = (lc[r.level] || 0) + 1; });
  svgHBars('sigma-bars', [
    { label: 'critical', value: lc.critical || 0, color: '#f85149' },
    { label: 'high', value: lc.high || 0, color: '#f0a500' },
    { label: 'medium', value: lc.medium || 0, color: '#d29922' },
    { label: 'low', value: lc.low || 0, color: '#8b949e' },
  ], '개');
}

function sigmaMatchRow(m) {
  return `
    <tr style="background:rgba(248,81,73,${m.severity === 'CRITICAL' ? '.10' : '.05'})">
      <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((m.timestamp || '').slice(11))}</td>
      <td>${sigmaLevelBadge(m.level)}</td>
      <td class="small" style="color:#e6edf3">${escapeHtml(m.rule)}</td>
      <td class="small font-monospace text-truncate" style="max-width:260px;color:#e6edf3"
          title="${escapeHtml(m.cmdline || m.image || '')}">${escapeHtml(m.cmdline || m.image || '-')}</td>
      <td class="small">${(m.mitre || []).map(x => `<span class="badge bg-dark" style="font-size:9px">${escapeHtml(x)}</span>`).join(' ') || '-'}</td>
    </tr>`;
}
function renderSigmaMatches() {
  const tb = document.getElementById('sigma-matches-tbody');
  if (!tb) return;
  tb.innerHTML = sigmaMatchBuffer.length
    ? sigmaMatchBuffer.slice(0, 60).map(sigmaMatchRow).join('')
    : '<tr><td colspan="5" class="text-muted text-center p-3">매치 없음</td></tr>';
}

function toggleSigma(rid) {
  fetch('/api/sigma/toggle', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule_id: rid })
  }).then(r => r.json()).then(() => loadSigma()).catch(() => {});
}

socket.on('sigma_match', m => {
  sigmaMatchBuffer.unshift(m);
  while (sigmaMatchBuffer.length > 300) sigmaMatchBuffer.pop();
  const bump = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g,''))||0)+n).toLocaleString(); };
  bump('sigma-matches', 1);
  const badge = document.getElementById('sidebar-sigma-count');
  if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g,''))||0)+1).toLocaleString();
  pushLive('sigma', (m.severity || 'medium').toLowerCase(),
    `<b>Sigma: ${escapeHtml(m.rule)}</b> ` +
    `<span class="font-monospace">${escapeHtml((m.cmdline || m.image || '').slice(0, 50))}</span>`);
  if (!document.getElementById('panel-sigma')?.classList.contains('d-none')) renderSigmaMatches();
});

/* ════════════════════ 취약점 패치 (Ansible) ════════════════════ */
/* ══════════════ 취약점 스캔 (포트/서비스/CVE) ══════════════ */
let _vulnHostsInit = false;
let _vulnResults = {};      // host id -> result

const VSEV = {
  critical: { c: '#ff3b6b', t: 'CRIT' }, high: { c: '#f85149', t: 'HIGH' },
  medium: { c: '#f79000', t: 'MED' }, low: { c: '#d29922', t: 'LOW' },
  info: { c: '#39d0d8', t: 'INFO' },
};
function vsevBadge(sev) {
  const s = VSEV[sev] || VSEV.info;
  return `<span class="badge" style="background:${s.c};color:#0d1117;font-size:9px;font-weight:700">${s.t}</span>`;
}

const VVERDICT = {
  vulnerable: { c: '#f85149', t: '미패치 · 정탐유력' },
  patched: { c: '#3fb950', t: '패치됨 · 오탐유력' },
  unknown: { c: '#6e7681', t: '미확인' },
};
function vulnVerdict(v) {
  if (!v) return '';
  const s = VVERDICT[v.state] || VVERDICT.unknown;
  const ver = v.installed
    ? `<span class="text-muted font-monospace" style="font-size:10px">설치: ${escapeHtml(v.installed)}${v.candidate ? ' → ' + escapeHtml(v.candidate) : ''}</span>` : '';
  return `<div class="mt-1"><span class="badge" style="background:${s.c};color:#0d1117;font-size:9px;font-weight:700"
    title="${escapeHtml(v.note || '')}">${s.t}</span> ${ver}
    <div class="small text-muted" style="font-size:10px">${escapeHtml(v.note || '')}</div></div>`;
}

function loadVulnScan() {
  fetch('/api/vulnscan/status').then(r => r.json()).then(renderVulnScan).catch(() => {});
}

function renderVulnScan(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('vuln-open', stats.open_ports);
  set('vuln-total', stats.vulns);
  set('vuln-high', (stats.high || 0) + (stats.critical || 0));
  set('vuln-hosts', stats.hosts);
  const sb = document.getElementById('sidebar-vuln-count');
  if (sb) sb.textContent = ((stats.high || 0) + (stats.critical || 0)).toLocaleString();

  const badge = document.getElementById('vuln-mode-badge');
  if (badge) {
    const real = stats.mode === 'real';
    badge.textContent = real ? '실측' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
    badge.style.background = real ? 'var(--green)' : '#30363d';
    badge.style.color = real ? '#001417' : '#e6edf3';
  }
  const eng = document.getElementById('vuln-engine-badge');
  if (eng) {
    eng.textContent = stats.nmap ? 'nmap' : 'socket 스캔';
    eng.style.background = stats.nmap ? 'var(--purple)' : '#30363d';
    eng.style.color = stats.nmap ? '#0d1117' : '#e6edf3';
  }
  const note = document.getElementById('vuln-mode-note');
  if (note) note.textContent = '(응답하는 대상은 실측 스캔 · 응답 없는 대상만 데모 샘플)';

  setVulnScanning(stats.scanning);
  renderVulnHosts(d.hosts || []);

  _vulnResults = {};
  (d.results || []).forEach(r => { _vulnResults[r.id] = r; });
  renderVulnResults();
  renderVulnHistory(d.history || []);
}

function setVulnScanning(on) {
  const btn = document.getElementById('vuln-scan-btn');
  const st = document.getElementById('vuln-scan-status');
  if (btn) btn.disabled = !!on;
  if (st) st.innerHTML = on
    ? '<i class="fa fa-spinner fa-spin me-1"></i>스캔 중...'
    : '';
}

function renderVulnHosts(hosts) {
  const box = document.getElementById('vuln-hosts-list');
  if (!box) return;
  const prev = vulnSelectedHosts();
  box.innerHTML = hosts.map(h => {
    const checked = _vulnHostsInit ? (prev.includes(h.id) ? 'checked' : '') : 'checked';
    const remote = h.conn === 'ssh';
    return `<label class="d-flex align-items-center gap-1 small" style="color:#e6edf3">
      <input type="checkbox" class="vuln-host" value="${escapeHtml(h.id)}" ${checked}>
      <i class="fa ${remote ? 'fa-network-wired text-orange' : 'fa-desktop text-cyan'}" style="font-size:11px"></i>
      ${escapeHtml(h.name)}<span class="text-muted font-monospace" style="font-size:10px">(${escapeHtml(h.addr)})</span>
    </label>`;
  }).join('') || '<span class="text-muted small">호스트 없음</span>';
  _vulnHostsInit = true;
}

function vulnSelectedHosts() {
  return Array.from(document.querySelectorAll('.vuln-host:checked')).map(c => c.value);
}
function vulnSelectAllHosts(on) {
  document.querySelectorAll('.vuln-host').forEach(c => { c.checked = on; });
}

function vulnScan() {
  const hosts = vulnSelectedHosts();
  if (!hosts.length) { alert('스캔할 서버를 하나 이상 선택하세요.'); return; }
  setVulnScanning(true);
  fetch('/api/vulnscan/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hosts }),
  }).then(r => r.json()).then(res => {
    if (res.status === 'busy') { setVulnScanning(false); alert(res.msg || '이미 스캔 중입니다.'); }
  }).catch(() => setVulnScanning(false));
}

function renderVulnResults() {
  const box = document.getElementById('vuln-results');
  if (!box) return;
  const list = Object.values(_vulnResults);
  if (!list.length) {
    box.innerHTML = '<div class="text-muted p-3 text-center">아직 스캔하지 않았습니다. 대상 선택 후 <strong>스캔</strong>을 누르세요.</div>';
    updateVulnSevChart();
    return;
  }
  box.innerHTML = list.map(r => {
    const rows = (r.ports || []).map(p => {
      const items = (p.cves || []).map(c =>
        `<div class="small">${vsevBadge(c.severity)} <span class="font-monospace text-danger">${escapeHtml(c.cve)}</span>
          <span class="text-muted">${escapeHtml(c.desc || '')}</span></div>`).join('')
        + (p.findings || []).map(f =>
        `<div class="small">${vsevBadge(f.severity)} <span class="text-orange">노출</span>
          <span class="text-muted">${escapeHtml(f.desc || '')}</span></div>`).join('');
      const demo = p.demo ? '<span class="demo-badge ms-1">데모</span>' : '';
      return `<tr>
        <td class="font-monospace text-cyan" style="white-space:nowrap">${p.port}</td>
        <td class="small" style="color:#e6edf3">${escapeHtml(p.service || '')}</td>
        <td class="small text-muted font-monospace text-truncate" style="max-width:180px" title="${escapeHtml(p.version || '')}">${escapeHtml(p.version || '—')}</td>
        <td>${vsevBadge(p.severity)}${demo}${vulnVerdict(p.verdict)}<div class="mt-1">${items || '<span class="small text-muted">알려진 취약점 없음</span>'}</div></td>
      </tr>`;
    }).join('');
    const remote = r.addr && r.addr !== '127.0.0.1';
    return `<div class="mb-3">
      <div class="d-flex align-items-center gap-2 mb-1">
        <i class="fa ${remote ? 'fa-network-wired text-orange' : 'fa-desktop text-cyan'}"></i>
        <strong style="color:#e6edf3">${escapeHtml(r.host)}</strong>
        <span class="text-muted font-monospace small">${escapeHtml(r.addr)}</span>
        <span class="badge bg-secondary ms-1" style="font-size:10px">열린 포트 ${r.open || 0}</span>
        <span class="badge bg-danger" style="font-size:10px">취약점 ${r.vulns || 0}</span>
        <span class="text-muted small ms-auto">${escapeHtml(r.scanned || '')}</span>
      </div>
      <div class="table-responsive">
        <table class="table table-dark table-sm mb-0" style="font-size:12px">
          <thead><tr><th style="width:60px">포트</th><th style="width:90px">서비스</th><th>버전</th><th>취약점 / 노출</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" class="text-muted text-center p-2">열린 포트 없음</td></tr>'}</tbody>
        </table>
      </div>
    </div>`;
  }).join('');
  updateVulnSevChart();
}

function updateVulnSevChart() {
  const cnt = { critical: 0, high: 0, medium: 0, low: 0 };
  Object.values(_vulnResults).forEach(r => (r.ports || []).forEach(p => {
    [...(p.cves || []), ...(p.findings || [])].forEach(x => {
      if (cnt[x.severity] !== undefined) cnt[x.severity]++;
    });
  }));
  svgHBars('vuln-sev-bars', [
    { label: 'Critical', value: cnt.critical, color: VSEV.critical.c },
    { label: 'High', value: cnt.high, color: VSEV.high.c },
    { label: 'Medium', value: cnt.medium, color: VSEV.medium.c },
    { label: 'Low', value: cnt.low, color: VSEV.low.c },
  ]);
}

function renderVulnHistory(hist) {
  const box = document.getElementById('vuln-history');
  if (!box) return;
  box.innerHTML = hist.length
    ? hist.map(h => `<div class="p-1 border-bottom border-secondary small" style="color:#e6edf3">
        <i class="fa fa-radar text-cyan me-1"></i>${escapeHtml(h.ts)}
        <span class="text-muted ms-1">서버 ${h.hosts} · 포트 ${h.open_ports} · 취약 ${h.vulns}</span></div>`).join('')
    : '<div class="text-muted p-2">이력 없음</div>';
}

socket.on('vulnscan_host', res => {
  _vulnResults[res.id] = res;
  renderVulnResults();
});
socket.on('vulnscan_status', d => {
  const stats = (d && d.stats) || {};
  setVulnScanning(stats.scanning);
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('vuln-open', stats.open_ports);
  set('vuln-total', stats.vulns);
  set('vuln-high', (stats.high || 0) + (stats.critical || 0));
  const sb = document.getElementById('sidebar-vuln-count');
  if (sb) sb.textContent = ((stats.high || 0) + (stats.critical || 0)).toLocaleString();
});

/* ══════════════ 웹 퍼징 (견고성) ══════════════ */
const FTYPE = {
  server_error: { c: '#f85149', t: '5xx' }, timeout: { c: '#f79000', t: '응답없음' },
  reflection: { c: '#a371f7', t: '입력반사' }, latency: { c: '#d29922', t: '지연' },
};
let _fuzzTargetsInit = false;

function loadFuzz() {
  fetch('/api/fuzz/status').then(r => r.json()).then(renderFuzz).catch(() => {});
}

function renderFuzz(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('fuzz-requests', stats.requests);
  set('fuzz-5xx', stats.errors_5xx);
  set('fuzz-timeouts', stats.timeouts);
  set('fuzz-reflections', stats.reflections);
  const sb = document.getElementById('sidebar-fuzz-count');
  if (sb) sb.textContent = (stats.findings || 0).toLocaleString();

  const eng = document.getElementById('fuzz-engine-badge');
  if (eng) { eng.textContent = stats.engine || '-'; eng.style.background = 'var(--purple)'; eng.style.color = '#0d1117'; }
  const rn = document.getElementById('fuzz-rate-note');
  const pc = document.getElementById('fuzz-payload-count');
  if (pc) pc.textContent = d.payload_count ?? '-';
  const mn = document.getElementById('fuzz-mode-note');
  if (mn) mn.textContent = stats.allow_write ? '(POST 허용됨)' : '(GET 전용 잠금)';

  // 대상 select — 최초 1회 채움(공인 IP는 비활성)
  const sel = document.getElementById('fuzz-target');
  if (sel && !_fuzzTargetsInit) {
    sel.innerHTML = (d.targets || []).map(t =>
      `<option value="${escapeHtml(t.id)}" ${t.private ? '' : 'disabled'}>
        ${escapeHtml(t.name)} — ${escapeHtml(t.base)}${t.private ? '' : ' (공인 IP 불가)'}</option>`).join('');
    _fuzzTargetsInit = true;
  }
  if (rn) rn.textContent = 'rate limit';

  setFuzzing(stats.fuzzing);
  renderFuzzFindings(d.findings || []);
  renderFuzzHistory(d.history || []);
}

function setFuzzing(on) {
  const btn = document.getElementById('fuzz-run-btn');
  const st = document.getElementById('fuzz-run-status');
  if (btn) btn.disabled = !!on;
  if (st) st.innerHTML = on ? '<i class="fa fa-spinner fa-spin me-1"></i>퍼징 중...' : '';
}

function fuzzRun() {
  const target = document.getElementById('fuzz-target').value;
  const paths = document.getElementById('fuzz-paths').value.split(',').map(s => s.trim()).filter(Boolean);
  const params = document.getElementById('fuzz-params').value.split(',').map(s => s.trim()).filter(Boolean);
  const method = document.getElementById('fuzz-method').value;
  if (method === 'POST' && !confirm('POST(쓰기) 퍼징은 서버 상태를 바꿀 수 있습니다. 계속할까요?')) return;
  setFuzzing(true);
  fetch('/api/fuzz/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, paths, params, method }),
  }).then(r => r.json()).then(res => {
    if (res.status !== 'started') { setFuzzing(false); alert(res.msg || res.status); }
  }).catch(() => setFuzzing(false));
}

function fuzzStop() {
  fetch('/api/fuzz/stop', { method: 'POST' }).catch(() => {});
}

let _fuzzFindings = [];
function renderFuzzFindings(list) {
  _fuzzFindings = list.slice();
  drawFuzzFindings();
}
function drawFuzzFindings() {
  const tb = document.getElementById('fuzz-findings-tbody');
  if (!tb) return;
  tb.innerHTML = _fuzzFindings.length
    ? _fuzzFindings.map(f => {
      const ty = FTYPE[f.type] || { c: '#6e7681', t: f.type };
      return `<tr>
        <td class="small text-muted font-monospace">${escapeHtml(f.time || '')}</td>
        <td>${vsevBadge(f.severity)} <span class="small" style="color:${ty.c}">${escapeHtml(ty.t)}</span></td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(f.path || '')}<span class="text-muted">?${escapeHtml(f.param || '')}</span></td>
        <td class="small"><span class="badge bg-secondary" style="font-size:9px">${escapeHtml(f.payload_label || '')}</span>
          <div class="text-muted font-monospace text-truncate" style="max-width:150px" title="${escapeHtml(f.payload || '')}">${escapeHtml(f.payload || '')}</div></td>
        <td class="small font-monospace" style="color:#e6edf3">${f.status ?? '—'}<div class="text-muted" style="font-size:10px">${f.elapsed_ms ?? 0}ms</div></td>
        <td class="small text-muted">${escapeHtml(f.desc || '')}</td>
      </tr>`;
    }).join('')
    : '<tr><td colspan="6" class="text-muted text-center p-3">발견 없음 — 서버가 입력을 안전하게 처리 중</td></tr>';

  const cnt = { server_error: 0, timeout: 0, reflection: 0, latency: 0 };
  _fuzzFindings.forEach(f => { if (cnt[f.type] !== undefined) cnt[f.type]++; });
  svgHBars('fuzz-type-bars', [
    { label: '5xx/미처리', value: cnt.server_error, color: FTYPE.server_error.c },
    { label: '응답없음', value: cnt.timeout, color: FTYPE.timeout.c },
    { label: '입력반사', value: cnt.reflection, color: FTYPE.reflection.c },
    { label: '지연', value: cnt.latency, color: FTYPE.latency.c },
  ]);
}

function renderFuzzHistory(hist) {
  const box = document.getElementById('fuzz-history');
  if (!box) return;
  box.innerHTML = hist.length
    ? hist.map(h => `<div class="p-1 border-bottom border-secondary small" style="color:#e6edf3">
        <i class="fa fa-bug text-danger me-1"></i>${escapeHtml(h.ts)}
        <div class="text-muted" style="font-size:10.5px">${escapeHtml(h.target)} · ${escapeHtml(h.method)} · 요청 ${h.requests} · 발견 ${h.findings}${h.stopped ? ' · 중단됨' : ''}</div></div>`).join('')
    : '<div class="text-muted p-2">이력 없음</div>';
}

socket.on('fuzz_finding', f => {
  _fuzzFindings.unshift(f);
  if (_fuzzFindings.length > 80) _fuzzFindings.pop();
  drawFuzzFindings();
});
socket.on('fuzz_status', d => {
  const stats = (d && d.stats) || {};
  setFuzzing(stats.fuzzing);
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('fuzz-requests', stats.requests);
  set('fuzz-5xx', stats.errors_5xx);
  set('fuzz-timeouts', stats.timeouts);
  set('fuzz-reflections', stats.reflections);
  const sb = document.getElementById('sidebar-fuzz-count');
  if (sb) sb.textContent = (stats.findings || 0).toLocaleString();
  if (!stats.fuzzing) setTimeout(loadFuzz, 300);   // 종료 후 이력/발견 최종 동기화
});

function loadPatch(rescan) {
  const url = rescan ? '/api/patch/scan' : '/api/patch/status';
  fetch(url, rescan ? { method: 'POST' } : {}).then(r => r.json()).then(renderPatch).catch(() => {});
}

function renderPatch(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('patch-upgradable', stats.upgradable);
  set('patch-security', stats.security);
  set('patch-jobs', stats.jobs_run);
  const ansEl = document.getElementById('patch-ansible');
  if (ansEl) ansEl.textContent = stats.ansible ? '있음' : '미설치';
  const badge = document.getElementById('patch-mode-badge');
  const note = document.getElementById('patch-mode-note');
  if (badge) {
    const real = stats.mode === 'real';
    badge.textContent = real ? '실측 (apt)' : (stats.mode === 'demo' ? '데모 모드' : '비활성');
    badge.style.background = real ? 'var(--green)' : '#30363d';
    badge.style.color = real ? '#001417' : '#e6edf3';
  }
  if (note) {
    const parts = [];
    if (stats.mode === 'demo') parts.push('데모 취약 패키지 표시 중 (실서버는 apt 실스캔)');
    parts.push(stats.apply_enabled ? '실제 적용 허용됨' : '실제 적용 잠금(dry-run만)');
    note.textContent = '(' + parts.join(' · ') + ')';
  }
  const sbadge = document.getElementById('sidebar-patch-count');
  if (sbadge) sbadge.textContent = (stats.security || 0).toLocaleString();

  const tb = document.getElementById('patch-inv-tbody');
  if (tb) {
    const inv = d.inventory || [];
    tb.innerHTML = inv.length
      ? inv.map(p => `
        <tr ${p.security ? 'style="background:rgba(248,81,73,.06)"' : ''}>
          <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(p.package)}
            ${p.cve ? `<span class="badge bg-danger ms-1" style="font-size:9px">${escapeHtml(p.cve)}</span>` : ''}</td>
          <td class="small text-muted"><span class="font-monospace">${escapeHtml(p.current)}</span> →
            <span class="font-monospace text-success">${escapeHtml(p.candidate)}</span></td>
          <td>${p.security ? '<span class="badge bg-danger" style="font-size:10px">보안</span>' : '<span class="badge bg-secondary" style="font-size:10px">일반</span>'}</td>
        </tr>`).join('')
      : '<tr><td colspan="3" class="text-muted text-center p-3">업데이트 없음 (최신)</td></tr>';
  }
  renderPatchHosts(d.hosts || []);
  renderPatchJobs(d.jobs || []);

  const up = stats.upgradable || 0, sec = stats.security || 0;
  svgDonut('patch-donut', [
    { label: '보안 패치', value: sec, color: '#f85149' },
    { label: '일반 업데이트', value: Math.max(0, up - sec), color: '#39d0d8' },
  ], up.toLocaleString(), '업그레이드 가능');
}

/* 대상 서버 체크박스 — 갱신 시 기존 선택 유지, 최초엔 localhost 기본 선택 */
let _patchHostsInit = false;
function renderPatchHosts(hosts) {
  const box = document.getElementById('patch-hosts');
  if (!box) return;
  const prev = patchSelectedHosts();          // 현재 선택 보존
  box.innerHTML = hosts.map(h => {
    const checked = _patchHostsInit
      ? (prev.includes(h.id) ? 'checked' : '')
      : (h.conn === 'local' ? 'checked' : '');   // 최초: localhost만
    const remote = h.conn === 'ssh';
    return `<label class="d-flex align-items-center gap-1 small" style="color:#e6edf3">
      <input type="checkbox" class="patch-host" value="${escapeHtml(h.id)}" ${checked}>
      <i class="fa ${remote ? 'fa-network-wired text-orange' : 'fa-desktop text-cyan'}" style="font-size:11px"></i>
      ${escapeHtml(h.name)}${remote ? `<span class="text-muted font-monospace" style="font-size:10px">(${escapeHtml(h.addr)})</span>` : ''}
    </label>`;
  }).join('') || '<span class="text-muted small">호스트 없음</span>';
  _patchHostsInit = true;
}

function patchSelectedHosts() {
  return Array.from(document.querySelectorAll('.patch-host:checked')).map(c => c.value);
}

function patchSelectAllHosts(on) {
  document.querySelectorAll('.patch-host').forEach(c => { c.checked = on; });
}

function renderPatchJobs(jobs) {
  const box = document.getElementById('patch-jobs-list');
  if (!box) return;
  const statusColor = { success: 'var(--green)', simulated: 'var(--cyan)', failed: 'var(--red)', blocked: 'var(--orange)', running: 'var(--yellow,#d29922)' };
  box.innerHTML = jobs.length
    ? jobs.map(j => `
      <div class="p-1 border-bottom border-secondary small" style="cursor:pointer" onclick='showPatchLog(${JSON.stringify(j).replace(/'/g, "&#39;")})'>
        <span class="badge" style="background:${statusColor[j.status] || '#555'};font-size:9px">${escapeHtml(j.status)}</span>
        <span style="color:#e6edf3" class="ms-1">#${j.id} ${j.kind === 'command'
          ? `<i class="fa fa-terminal me-1"></i><span class="font-monospace">${escapeHtml((j.command || '').slice(0, 32))}</span>`
          : `${j.mode === 'check' ? 'Dry-run' : j.mode} ${j.security_only ? '(보안만)' : '(전체)'}`}
          ${Array.isArray(j.hosts) && j.hosts.length ? `<span class="text-muted" style="font-size:9px">· ${escapeHtml(j.hosts.join(', '))}</span>` : ''}</span>
        <div class="text-muted" style="font-size:10px">${escapeHtml(j.result || '')}</div>
      </div>`).join('')
    : '<div class="text-muted p-2">작업 없음</div>';
}

function showPatchLog(job) {
  const out = document.getElementById('patch-output');
  if (!out) return;
  const head = job.kind === 'command'
    ? `# 작업 #${job.id} [${job.status}] 명령: ${job.command || ''}`
    : `# 작업 #${job.id} [${job.status}] ${job.result || ''}\n# 플레이북: ${job.playbook || ''}`;
  const hosts = Array.isArray(job.hosts) && job.hosts.length ? `\n# 대상: ${job.hosts.join(', ')}` : '';
  out.textContent = `${head}${hosts}\n\n${job.log || '(로그 없음)'}`;
}

function patchPlaybook() {
  fetch('/api/patch/playbook', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ security_only: true })
  }).then(r => r.json()).then(d => {
    const out = document.getElementById('patch-output');
    if (out) out.textContent = `# 생성됨: ${d.path}\n# 검토 후 실행: ansible-playbook -i localhost, -c local ${d.path}\n\n${d.content}`;
  }).catch(() => {});
}

function patchRun(mode) {
  const hosts = patchSelectedHosts();
  if (!hosts.length) { alert('대상 서버를 하나 이상 선택하세요.'); return; }
  const label = mode === 'apply' ? '일괄 실제 적용' : 'Dry-run(점검)';
  if (mode === 'apply' && !confirm(`선택한 ${hosts.length}대 서버에 실제 패치를 적용합니다.\n운영 중 자동매매 봇이 영향받을 수 있습니다. 점검 시간대인가요?\n(PATCH_APPLY_ENABLED=False면 자동 차단됩니다)`)) return;
  const out = document.getElementById('patch-output');
  if (out) out.textContent = `${label} 실행 중... (대상 ${hosts.length}대)`;
  fetch('/api/patch/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, security_only: true, hosts })
  }).then(r => r.json()).then(() => {
    setTimeout(() => loadPatch(), 1200);   // 작업 완료 후 이력/로그 갱신
  }).catch(() => { if (out) out.textContent = '실행 요청 실패'; });
}

function patchCommand(mode) {
  const hosts = patchSelectedHosts();
  if (!hosts.length) { alert('대상 서버를 하나 이상 선택하세요.'); return; }
  const input = document.getElementById('patch-cmd-input');
  const command = (input?.value || '').trim();
  if (!command) { alert('실행할 명령을 입력하세요.'); return; }
  if (mode === 'apply' && !confirm(`선택한 ${hosts.length}대 서버에서 명령을 실제 실행합니다:\n\n${command}\n\n(PATCH_APPLY_ENABLED=False면 차단, 파괴적 명령은 자동 차단)`)) return;
  const out = document.getElementById('patch-output');
  if (out) out.textContent = `${mode === 'apply' ? '명령 실행' : '미리보기'} 중... (대상 ${hosts.length}대)`;
  fetch('/api/patch/command', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command, mode, hosts })
  }).then(r => r.json()).then(() => {
    setTimeout(() => loadPatch(), 1000);
  }).catch(() => { if (out) out.textContent = '명령 요청 실패'; });
}

socket.on('patch_job', j => {
  if (document.getElementById('panel-patch')?.classList.contains('d-none')) return;
  loadPatch();
  showPatchLog(j);
});

/* ════════════════════ 푸시 알림 (ntfy) ════════════════════ */
function loadNotify() {
  fetch('/api/notify/status').then(r => r.json()).then(renderNotify).catch(() => {});
}

function renderNotify(d) {
  const stats = d.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = (v ?? 0).toLocaleString(); };
  set('notify-sent', stats.sent);
  set('notify-suppressed', stats.suppressed);
  set('notify-failed', stats.failed);
  const srvEl = document.getElementById('notify-server');
  if (srvEl) srvEl.textContent = (d.server || '-').replace(/^https?:\/\//, '');
  const minEl = document.getElementById('notify-minsev');
  if (minEl) minEl.textContent = d.min_severity || 'CRITICAL';

  const badge = document.getElementById('notify-mode-badge');
  const note = document.getElementById('notify-mode-note');
  if (badge) {
    badge.textContent = d.active ? '활성 (폰 연결됨)' : '비활성 (미설정)';
    badge.style.background = d.active ? 'var(--green)' : '#30363d';
    badge.style.color = d.active ? '#001417' : '#e6edf3';
  }
  if (note) note.textContent = d.active ? '' : '(NTFY_ENABLED=True + NTFY_TOPIC 설정 후 재시작하면 폰으로 알림)';

  const tb = document.getElementById('notify-hist-tbody');
  if (tb) {
    const h = d.history || [];
    tb.innerHTML = h.length
      ? h.map(e => `
        <tr>
          <td class="small" style="color:#e6edf3;white-space:nowrap">${escapeHtml((e.timestamp || '').slice(11))}</td>
          <td><span class="badge" style="background:${sevColor(e.severity)};font-size:9px">${escapeHtml(e.severity)}</span></td>
          <td class="small" style="color:#e6edf3">${escapeHtml(e.title)}</td>
          <td class="small">${e.delivered ? '<span class="text-success">전송✓</span>' : `<span class="text-muted">${escapeHtml(e.detail || '미전송')}</span>`}</td>
        </tr>`).join('')
      : '<tr><td colspan="4" class="text-muted text-center p-3">이력 없음</td></tr>';
  }

  svgHBars('notify-bars', [
    { label: '전송 성공', value: stats.sent || 0, color: '#3fb950' },
    { label: '쿨다운 억제', value: stats.suppressed || 0, color: '#f0a500' },
    { label: '실패', value: stats.failed || 0, color: '#f85149' },
  ], '건');
}

function notifyTest() {
  const res = document.getElementById('notify-test-result');
  if (res) { res.textContent = '전송 중...'; res.className = 'small ms-2 text-muted'; }
  fetch('/api/notify/test', { method: 'POST' }).then(r => r.json()).then(d => {
    if (!res) return;
    if (d.ok) { res.textContent = '✓ ' + d.detail; res.className = 'small ms-2 text-success'; }
    else { res.textContent = (d.active ? '실패: ' : '비활성 — .env 설정 필요: ') + d.detail; res.className = 'small ms-2 text-warning'; }
    loadNotify();
  }).catch(() => { if (res) res.textContent = '요청 실패'; });
}

socket.on('notify_event', e => {
  if (document.getElementById('panel-notify')?.classList.contains('d-none')) return;
  loadNotify();
});

/* ════════════════════ SOAR 자동 대응 ════════════════════ */
function loadSoar() {
  fetch('/api/soar/status')
    .then(r => r.json())
    .then(renderSoar)
    .catch(() => {});
}

let _soarStatus = null;   // 판정 상세 모달이 참조할 최신 SOAR 상태 캐시

function renderSoar(d) {
  _soarStatus = d;
  const stats = d.stats || {};
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (v ?? 0).toLocaleString();
  };
  set('soar-total-actions', stats.total_actions);
  set('soar-blocked', stats.auto_blocked);
  set('soar-closed-fp', stats.auto_closed_fp);
  set('soar-escalated', stats.escalated_tp);
  set('sidebar-soar-count', stats.total_actions);
  const modeEl = document.getElementById('soar-mode-label');
  if (modeEl) modeEl.textContent = d.block_mode || 'simulate';
  // 안전장치 정보
  const safety = d.safety || {};
  const prevEl = document.getElementById('soar-prevented');
  if (prevEl) prevEl.textContent = (safety.prevented || 0).toLocaleString();
  const extraEl = document.getElementById('soar-safety-extra');
  if (extraEl) {
    const allow = safety.allowlist || [];
    extraEl.innerHTML = allow.length
      ? `추가 화이트리스트: <span class="font-monospace text-warning">${allow.map(escapeHtml).join(', ')}</span>. `
      : '';
  }
  // 파이프라인: AI 트리아지 + SOAR 대응
  setPipe('pipe-ai-triage', stats.ai_triages);
  setPipe('pipe-ai-tp', stats.escalated_tp);
  setPipe('pipe-ai-fp', stats.auto_closed_fp);
  setPipe('pipe-soar-actions', stats.total_actions);
  setPipe('pipe-soar-blocked', stats.auto_blocked);

  // 플레이북
  const pbBox = document.getElementById('soar-playbooks');
  if (pbBox) {
    pbBox.innerHTML = (d.playbooks || []).map(pb => `
      <div class="d-flex align-items-center gap-2 p-2 border-bottom border-secondary">
        <div class="form-check form-switch mb-0">
          <input class="form-check-input" type="checkbox" ${pb.enabled ? 'checked' : ''}
                 onchange="soarTogglePb('${escapeHtml(pb.id)}')">
        </div>
        <div class="flex-fill">
          <div class="small fw-bold" style="color:#e6edf3">${escapeHtml(pb.name)}</div>
          <div class="small text-muted" style="font-size:10px">${escapeHtml(pb.description)}</div>
        </div>
        <div class="text-end small text-muted" style="font-size:10px; white-space:nowrap">
          실행 ${pb.runs}회${pb.last_run ? `<br/>${escapeHtml(pb.last_run)}` : ''}
        </div>
      </div>`).join('');
  }

  // 차단 IP 목록
  const blBox = document.getElementById('soar-blocklist');
  if (blBox) {
    const ips = d.blocked_ips || [];
    blBox.innerHTML = ips.length
      ? ips.map(b => `
          <div class="d-flex align-items-center p-1 border-bottom border-secondary small">
            <span class="font-monospace text-danger me-2">${escapeHtml(b.ip)}</span>
            <span class="badge ${b.mode === 'simulate' ? 'bg-secondary' : 'bg-danger'}"
                  style="font-size:9px">${escapeHtml(b.mode)}</span>
            <span class="text-muted ms-2 text-truncate" style="font-size:10px; max-width:150px"
                  title="${escapeHtml(b.reason)}">${escapeHtml(b.reason)}</span>
            <span class="text-warning ms-1" style="font-size:9px; white-space:nowrap"
                  title="자동 만료 시각">${escapeHtml((b.expires || '').replace(/^\d{4}-/, ''))}</span>
            <button class="btn btn-xs btn-outline-secondary ms-auto" style="font-size:9px"
                    onclick="soarUnblock('${escapeHtml(b.ip)}')">해제</button>
          </div>`).join('')
      : '<div class="text-muted p-2">차단된 IP 없음</div>';
  }

  // 대응 타임라인
  const tbody = document.getElementById('soar-actions-tbody');
  if (tbody) {
    const rows = (d.actions || []).map(soarActionRow).join('');
    tbody.innerHTML = rows || '<tr><td colspan="6" class="text-muted text-center p-3">아직 대응 이력 없음</td></tr>';
  }
}

// 정탐(tp)/오탐(fp) 카드·숫자 클릭 → SOAR 트리아지 상세 내역 모달
function showVerdictDetail(kind) {
  const isFp = kind === 'fp';
  const wantAction = isFp ? 'auto_close' : 'escalate';
  const title = isFp ? '오탐 자동 종결 내역' : '정탐 에스컬레이션 내역';
  const icon = isFp
    ? '<i class="fa fa-circle-check text-success me-2"></i>'
    : '<i class="fa fa-arrow-up-right-dots text-warning me-2"></i>';
  const titleEl = document.getElementById('verdict-detail-title');
  const bodyEl = document.getElementById('verdict-detail-body');
  const modalEl = document.getElementById('verdictDetailModal');
  if (!modalEl || !bodyEl) return;
  if (titleEl) titleEl.innerHTML = icon + escapeHtml(title);

  const render = (d) => {
    const stats = (d && d.stats) || {};
    const total = isFp ? (stats.auto_closed_fp || 0) : (stats.escalated_tp || 0);
    const rows = ((d && d.actions) || []).filter(a => a.action === wantAction);
    let html = `<div class="small text-muted mb-2">누적 ${total.toLocaleString()}건 · 최근 이력 ${rows.length}건 표시</div>`;
    if (!rows.length) {
      html += `<div class="text-center text-muted py-4">표시할 최근 ${isFp ? '오탐' : '정탐'} 내역이 없습니다.</div>`;
    } else {
      html += '<div class="list-group list-group-flush">' + rows.map(a => `
        <div class="list-group-item bg-transparent border-secondary px-0 py-2">
          <div class="d-flex align-items-center gap-2">
            <span class="badge ${isFp ? 'bg-success' : 'bg-warning text-dark'}">${isFp ? '오탐' : '정탐'}</span>
            <span class="fw-bold" style="color:#e6edf3">${escapeHtml(a.target || '')}</span>
            <span class="text-muted ms-auto small font-monospace">${escapeHtml(a.timestamp || '')}</span>
          </div>
          <div class="small mt-1" style="color:#c9d3de">${escapeHtml(a.detail || '')}</div>
        </div>`).join('') + '</div>';
    }
    bodyEl.innerHTML = html;
  };

  bodyEl.innerHTML = '<div class="text-center text-muted py-5">로딩 중...</div>';
  bootstrap.Modal.getOrCreateInstance(modalEl).show();

  if (_soarStatus) {
    render(_soarStatus);
  } else {
    fetch('/api/soar/status').then(r => r.json()).then(d => { _soarStatus = d; render(d); })
      .catch(() => { bodyEl.innerHTML = '<div class="text-center text-danger py-4">불러오기 실패</div>'; });
  }
}

const SOAR_ACTION_LABELS = {
  block_ip: '<span class="badge bg-danger">IP 차단</span>',
  unblock: '<span class="badge bg-secondary">차단 해제</span>',
  auto_close: '<span class="badge bg-success">오탐 종결</span>',
  escalate: '<span class="badge bg-warning text-dark">에스컬레이션</span>',
  triage: '<span class="badge bg-info text-dark">트리아지</span>',
  incident: '<span class="badge bg-danger">인시던트</span>',
};

function soarActionRow(a) {
  return `
    <tr>
      <td class="small" style="color:#e6edf3; white-space:nowrap">${escapeHtml((a.timestamp || '').split(' ')[1] || a.timestamp)}</td>
      <td class="small" style="white-space:nowrap"><span class="pb-tag">${escapeHtml(a.playbook)}</span></td>
      <td class="small">${SOAR_ACTION_LABELS[a.action] || escapeHtml(a.action)}</td>
      <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(a.target)}</td>
      <td class="small ${a.result === 'success' ? 'text-success' : 'text-muted'}">${escapeHtml(a.result)}</td>
      <td class="small text-truncate" style="max-width:260px; color:#e6edf3" title="${escapeHtml(a.detail)}">${escapeHtml(a.detail)}</td>
    </tr>`;
}

function soarTogglePb(pbId) {
  fetch(`/api/soar/playbooks/${encodeURIComponent(pbId)}/toggle`, { method: 'POST' })
    .then(r => r.json())
    .then(() => loadSoar());
}

function soarManualBlock() {
  const input = document.getElementById('soar-block-ip-input');
  const ip = (input?.value || '').trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) { alert('올바른 IPv4 주소를 입력하세요'); return; }
  fetch('/api/soar/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  }).then(r => r.json()).then(d => {
    if (input) input.value = '';
    loadSoar();
    if (!d.success) alert(d.message || '차단 실패');
  });
}

function soarUnblock(ip) {
  fetch('/api/soar/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  }).then(() => loadSoar());
}

/* ════════════════════ ML 의사결정 지원 ════════════════════ */
const DS_RECO_BADGES = {
  BLOCK:    '<span class="badge bg-danger">차단 권고</span>',
  FP_TUNE:  '<span class="badge bg-warning text-dark">오탐 튜닝</span>',
  CAMPAIGN: '<span class="badge bg-orange">캠페인 의심</span>',
  REVIEW:   '<span class="badge bg-info text-dark">수동 검토</span>',
  MONITOR:  '<span class="badge bg-secondary">관찰</span>',
};

function loadDecisionSupport() {
  fetch('/api/ml/decision')
    .then(r => r.json())
    .then(renderDecisionSupport)
    .catch(() => {});
}

function renderDecisionSupport(d) {
  const cEl = document.getElementById('ds-cluster-count');
  if (cEl) cEl.textContent = `${d.cluster_count || 0} 그룹`;
  const vEl = document.getElementById('ds-verdict-count');
  if (vEl) vEl.textContent = `판정 ${d.total_verdicts || 0}건 (오탐 ${d.total_fp || 0})`;

  const tbody = document.getElementById('ds-clusters-tbody');
  if (!tbody) return;
  const rows = (d.clusters || []).map(c => {
    const rate = c.tp_rate == null ? '-' : `${Math.round(c.tp_rate * 100)}%`;
    const rateCls = c.tp_rate == null ? 'text-muted'
                  : c.tp_rate >= 0.7 ? 'text-danger'
                  : c.tp_rate <= 0.3 ? 'text-success' : 'text-warning';
    return `
      <tr>
        <td class="small" style="color:${threatColor(c.threat_type)};font-weight:600">${escapeHtml(c.threat_type)}</td>
        <td class="small font-monospace" style="color:#e6edf3">${escapeHtml(c.src_net)}</td>
        <td class="small" style="color:#e6edf3">${c.count}</td>
        <td class="small" style="color:#e6edf3">${c.unique_ips}</td>
        <td class="small">${sevBadge(c.dominant_severity)}</td>
        <td class="small" style="color:#e6edf3">${c.tp} / ${c.fp}</td>
        <td class="small ${rateCls}">${rate}</td>
        <td class="small">${DS_RECO_BADGES[c.recommendation] || ''}
          <span style="color:#e6edf3" title="${escapeHtml(c.reason)}">${escapeHtml(c.reason)}</span></td>
      </tr>`;
  }).join('');
  tbody.innerHTML = rows || '<tr><td colspan="8" class="text-muted text-center p-3">아직 그룹 없음</td></tr>';
}

socket.on('decision_update', d => {
  if (!document.getElementById('panel-ml')?.classList.contains('d-none')) {
    renderDecisionSupport(d);
  }
});

/* ════════════════════ 인시던트 케이스 관리 ════════════════════ */
let selectedIncidentId = null;

const INC_STATUS_BADGES = {
  OPEN:          '<span class="badge bg-danger">OPEN</span>',
  INVESTIGATING: '<span class="badge bg-warning text-dark">INVESTIGATING</span>',
  CONTAINED:     '<span class="badge bg-info text-dark">CONTAINED</span>',
  RESOLVED:      '<span class="badge bg-success">RESOLVED</span>',
};
const INC_TL_ICONS = {
  open:   '<i class="fa fa-folder-plus text-danger"></i>',
  alert:  '<i class="fa fa-triangle-exclamation text-warning"></i>',
  block:  '<i class="fa fa-ban text-danger"></i>',
  status: '<i class="fa fa-arrows-rotate text-cyan"></i>',
  assign: '<i class="fa fa-user text-info"></i>',
  note:   '<i class="fa fa-pen text-secondary"></i>',
};

function loadIncidents() {
  fetch('/api/incidents')
    .then(r => r.json())
    .then(renderIncidents)
    .catch(() => {});
}

function renderIncidents(d) {
  const stats = d.stats || {};
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (v ?? 0).toLocaleString();
  };
  set('inc-active', stats.active);
  set('inc-investigating', stats.investigating);
  set('inc-contained', stats.contained);
  set('inc-resolved', stats.resolved);
  set('sidebar-inc-count', stats.active);
  setPipe('pipe-inc-active', stats.active);

  const tbody = document.getElementById('inc-tbody');
  if (!tbody) return;
  const rows = (d.incidents || []).map(inc => `
    <tr style="cursor:pointer" onclick="selectIncident(${inc.id})"
        ${inc.id === selectedIncidentId ? 'class="table-active"' : ''}>
      <td class="small text-cyan">#${inc.id}</td>
      <td class="small" style="color:#e6edf3">${escapeHtml(inc.title)}</td>
      <td class="small">${sevBadge(inc.severity)}</td>
      <td class="small">${INC_STATUS_BADGES[inc.status] || escapeHtml(inc.status)}</td>
      <td class="small" style="color:#e6edf3">${inc.alert_count}</td>
      <td class="small" style="color:#e6edf3">${escapeHtml(inc.assignee || '-')}</td>
      <td class="small text-muted" style="white-space:nowrap">${escapeHtml((inc.updated || '').slice(5))}</td>
    </tr>`).join('');
  tbody.innerHTML = rows || '<tr><td colspan="7" class="text-muted text-center p-3">인시던트 없음</td></tr>';

  if (selectedIncidentId) loadIncidentDetail(selectedIncidentId);
}

function selectIncident(id) {
  selectedIncidentId = id;
  loadIncidentDetail(id);
  loadIncidents();
}

function loadIncidentDetail(id) {
  fetch(`/api/incidents/${id}`)
    .then(r => r.json())
    .then(inc => {
      if (inc.error) return;
      const title = document.getElementById('inc-detail-title');
      if (title) title.textContent = `#${inc.id} ${inc.title}`;
      const controls = document.getElementById('inc-detail-controls');
      if (controls) controls.classList.remove('d-none');
      const sel = document.getElementById('inc-status-select');
      if (sel) sel.value = inc.status;
      const asg = document.getElementById('inc-assignee-input');
      if (asg) asg.value = inc.assignee || '';

      const box = document.getElementById('inc-timeline');
      if (box) {
        box.innerHTML = [...(inc.timeline || [])].reverse().map(t => `
          <div class="d-flex gap-2 p-2 border-bottom border-secondary small">
            <span>${INC_TL_ICONS[t.kind] || ''}</span>
            <span class="text-muted" style="white-space:nowrap; font-size:10px">${escapeHtml((t.ts || '').slice(5))}</span>
            <span style="color:#e6edf3">${escapeHtml(t.text)}</span>
          </div>`).join('') || '<div class="text-muted p-3 small">타임라인 없음</div>';
      }
    });
}

function saveIncident() {
  if (!selectedIncidentId) return;
  const status = document.getElementById('inc-status-select')?.value;
  const assignee = document.getElementById('inc-assignee-input')?.value ?? '';
  const noteInput = document.getElementById('inc-note-input');
  const note = (noteInput?.value || '').trim();
  fetch(`/api/incidents/${selectedIncidentId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, assignee, note: note || undefined }),
  }).then(() => {
    if (noteInput) noteInput.value = '';
    loadIncidents();
  });
}

socket.on('incident_update', d => {
  const badge = document.getElementById('sidebar-inc-count');
  if (badge && d.stats) badge.textContent = (d.stats.active || 0).toLocaleString();
  if (d.stats) setPipe('pipe-inc-active', d.stats.active);
  if (!document.getElementById('panel-incidents')?.classList.contains('d-none')) {
    renderIncidents(d);
  }
});

const SOAR_LIVE_LABEL = {
  block_ip: '🚫 IP 차단', unblock: '해제', auto_close: '✓ 오탐 자동종결',
  escalate: '▲ 정탐 에스컬레이션', triage: 'AI 트리아지', incident: '📁 인시던트 승격',
};

socket.on('soar_action', a => {
  const badge = document.getElementById('sidebar-soar-count');
  if (badge) badge.textContent = ((parseInt(badge.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
  // 파이프라인 즉시 반영
  incPipe('pipe-soar-actions');
  if (a.action === 'block_ip') incPipe('pipe-soar-blocked');
  if (a.action === 'auto_close') { incPipe('pipe-ai-fp'); incPipe('pipe-ai-triage'); }
  if (a.action === 'escalate') { incPipe('pipe-ai-tp'); incPipe('pipe-ai-triage'); }
  // 통합 라이브 스트림 (해제/트리아지 제외 — 핵심 대응만)
  if (!['unblock', 'triage'].includes(a.action)) {
    const sev = a.action === 'block_ip' ? 'critical'
              : a.action === 'escalate' ? 'high'
              : a.action === 'incident' ? 'high' : 'info';
    pushLive('soar', sev,
      `<b>${SOAR_LIVE_LABEL[a.action] || escapeHtml(a.action)}</b> ` +
      `<span class="lv-ip">${escapeHtml(a.target)}</span> ` +
      `<span class="pb-tag">${escapeHtml(a.playbook)}</span>`);
  }
  const tbody = document.getElementById('soar-actions-tbody');
  if (tbody && !document.getElementById('panel-soar').classList.contains('d-none')) {
    loadSoar();   // 패널 열려 있을 때만 전체 갱신 (KPI/차단목록 동기화)
  }
});

function incPipe(id) {
  const el = document.getElementById(id);
  if (el) el.textContent = ((parseInt(el.textContent.replace(/,/g, '')) || 0) + 1).toLocaleString();
}

/* ════════════════════ 초기화 ════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  showPanel('overview');

  // 초기 데이터 로드
  fetch('/api/dashboard/summary')
    .then(r => r.json())
    .then(d => {
      document.getElementById('stat-total-alerts').textContent = d.threats.total_alerts;
      setOpenAlerts(d.threats.open || 0);
      document.getElementById('stat-total-packets').textContent = d.packets.total_packets.toLocaleString();
      document.getElementById('stat-sysmon-events').textContent = d.sysmon.total_events.toLocaleString();
      document.getElementById('stat-ai-analyses').textContent   = d.ai.total_analyses;
    });

  // 초기 알림 + 개요 KPI 채우기
  fetch('/api/alerts?limit=200')
    .then(r => r.json())
    .then(d => {
      (d.alerts || []).slice(0, 5).forEach(a => prependOverviewAlert(a));
      let crit = 0, high = 0, closed = 0, open = 0;
      (d.alerts || []).forEach(a => {
        if (a.severity === 'CRITICAL') crit++;
        if (a.severity === 'HIGH') high++;
        if (a.status === 'CLOSED') closed++;
        if (a.status === 'OPEN')   open++;
        _attackerCounter[a.src_ip] = _attackerCounter[a.src_ip] || { count:0, type:a.threat_type };
        _attackerCounter[a.src_ip].count++;
        _threatTypeCounter[a.threat_label] = (_threatTypeCounter[a.threat_label] || 0) + 1;
      });
      document.getElementById('kpi-critical').textContent = crit;
      document.getElementById('kpi-high').textContent = high;
      document.getElementById('kpi-blocked').textContent = closed;
      document.getElementById('kpi-unique-attackers').textContent = Object.keys(_attackerCounter).length;
      setOpenAlerts(open);  // 미처리 알림만 사이드바 배지에 반영
      renderTopAttackers();
      renderThreatTypeChart();
      updateThreatLevel();
    });

  // 위협 인텔리전스 초기 상태
  loadThreatIntel();
  loadSiem();
  loadAuthlog();
  loadSoar();
  loadIncidents();

  // 마지막 갱신 시간 표시
  setInterval(() => {
    const el = document.getElementById('overview-last-update');
    if (el) el.textContent = '최종 갱신 ' + new Date().toLocaleTimeString('ko-KR', { hour12:false });
  }, 1000);

});
