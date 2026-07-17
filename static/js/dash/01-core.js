/* dashboard/01-core.js — 유틸·사이드바·패널전환·내 정보·시간
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
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

/* ─────────────────── 사이드바 접이식 그룹 ─────────────────── */
function toggleGroup(name) {
  const body = document.getElementById('sgroup-' + name);
  const head = document.getElementById('sgroup-head-' + name);
  if (!body || !head) return;
  const opened = !body.classList.toggle('collapsed');
  head.classList.toggle('open', opened);
}

function expandGroupFor(link) {
  const body = link.closest('.sidebar-group-body');
  if (!body) return;
  body.classList.remove('collapsed');
  const head = document.getElementById('sgroup-head-' + body.id.replace('sgroup-', ''));
  if (head) head.classList.add('open');
}

/* 그룹 헤더 배지: 하위 카운트 합산 (접혀 있어도 현황 파악 가능) */
function updateGroupBadges() {
  document.querySelectorAll('.sidebar-group-body').forEach(body => {
    const badge = document.getElementById('sgroup-badge-' + body.id.replace('sgroup-', ''));
    if (!badge) return;
    let sum = 0;
    body.querySelectorAll('.sidebar-link .badge').forEach(b => {
      const v = parseInt(String(b.textContent).replace(/[,%]/g, ''), 10);
      if (!isNaN(v) && b.id !== 'sidebar-purple-cov') sum += v;
    });
    badge.textContent = sum.toLocaleString();
    badge.classList.toggle('d-none', sum === 0);
  });
}
setInterval(updateGroupBadges, 3000);

/* ─────────────────── 패널 전환 ─────────────────── */
function showPanel(name) {
  document.querySelectorAll('.panel-section').forEach(p => p.classList.add('d-none'));
  const target = document.getElementById('panel-' + name);
  if (target) target.classList.remove('d-none');

  document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
  const link = document.querySelector(`[data-panel="${name}"]`);
  if (link) { link.classList.add('active'); expandGroupFor(link); }

  closeSidebar();   // 모바일: 패널 선택 시 드로어 닫기

  if (name === 'overview') setTimeout(initMap, 50);
  if (name === 'traffic') initTrafficCharts();
  if (name === 'alerts') loadAlerts();
  if (name === 'alert-history') loadAlertHistory();
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

