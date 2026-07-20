/* dashboard/02-overview.js — 개요 차트·핵심 소켓(패킷/알림/라이브스트림/Sysmon/AI/지도)
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
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

  if (isPanelVisible('overview')) {
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
  }

  // 패킷 테이블 (패킷 패널)
  if (isPanelVisible('packets')) updatePacketsTable(data.recent_packets || []);

  // 트래픽 패널 차트
  if (isPanelVisible('traffic')) updateTrafficCharts(data);
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
  if (typeof schedulePriorityReload === 'function') schedulePriorityReload();

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

let _liveRenderTimer = null;
function pushLive(kind, severity, html, meta) {
  const now = new Date().toTimeString().slice(0, 8);
  _liveBuffer.unshift({
    kind, severity: (severity || 'info').toLowerCase(), html, time: now,
    lowConf: !!(meta && meta.lowConf),   // 오탐 의심 알림 표시
  });
  while (_liveBuffer.length > LIVE_MAX) _liveBuffer.pop();
  // 이벤트 폭주 시 렉 방지 — 최대 ~3회/초로 렌더 배치
  if (!_liveRenderTimer) {
    _liveRenderTimer = setTimeout(() => { _liveRenderTimer = null; renderLiveStream(); }, 300);
  }
}

function renderLiveStream() {
  const box = document.getElementById('live-stream');
  if (!box) return;
  // 화면에 안 보이면 렌더 생략(오버뷰 패널이 숨겨져 있을 때 CPU 절약)
  const ov = document.getElementById('panel-overview');
  if (ov && ov.classList.contains('d-none')) return;
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
  if (isPanelVisible('sysmon')) updateSysmonTable(data.recent_events || []);
  if (isPanelVisible('overview')) renderOverviewSysmon(data.recent_events || []);
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
