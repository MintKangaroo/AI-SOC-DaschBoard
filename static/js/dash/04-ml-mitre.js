/* dashboard/04-ml-mitre.js — ML 자체 모델·MITRE ATT&CK
   (dashboard.js 원본 순서 유지 — 순서대로 로드) */
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

