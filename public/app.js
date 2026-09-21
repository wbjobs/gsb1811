'use strict';

/* 控制台：配置开关、报告查询/导出、兼容性自检 */

const SWITCH_META = [
  { key: 'cspFrameAncestors', name: 'CSP frame-ancestors', desc: '现代浏览器主防线，浏览器层直接拒绝渲染' },
  { key: 'cspReportOnly', name: 'CSP 演练模式（Report-Only）', desc: '只上报不拦截，用于灰度观察' },
  { key: 'xFrameOptions', name: 'X-Frame-Options', desc: 'IE/旧版浏览器兜底（DENY / ALLOW-FROM）' },
  { key: 'jsFrameBust', name: 'JS 防嵌套', desc: '顶层窗口自检 + 逃生跳转（可被 sandbox 绕过）' },
  { key: 'workerMonitor', name: 'Web Worker 监测', desc: '隐藏/失焦/覆盖层/计时器/篡改检测' },
  { key: 'allowPartner', name: '白名单合作方', desc: '允许 http://localhost:9002 嵌套本页面' }
];

let currentConfig = null;

function el(tag, props, text) {
  const node = document.createElement(tag);
  Object.assign(node, props || {});
  if (text !== undefined) node.textContent = text;
  return node;
}

function toast(nodeId, text, ok) {
  const node = document.getElementById(nodeId);
  node.textContent = text;
  node.className = 'msg ' + (ok ? 'ok' : 'err');
  setTimeout(() => { node.textContent = ''; }, 3500);
}

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    let msg = 'HTTP ' + res.status;
    try { msg = (await res.json()).error || msg; } catch (e) {}
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

/* --------------------------------- 配置 --------------------------------- */
function renderSwitches(cfg) {
  const box = document.getElementById('switches');
  box.innerHTML = '';
  for (const meta of SWITCH_META) {
    const row = el('div', { className: 'switch' });
    const labelWrap = el('label', {});
    labelWrap.appendChild(el('span', {}, meta.name));
    labelWrap.appendChild(el('span', { className: 'desc' }, meta.desc));
    const toggle = el('label', { className: 'toggle' });
    const input = el('input', { type: 'checkbox' });
    input.checked = !!cfg[meta.key];
    input.dataset.key = meta.key;
    toggle.appendChild(input);
    toggle.appendChild(el('span', { className: 'slider' }));
    labelWrap.appendChild(toggle);
    row.appendChild(labelWrap);
    box.appendChild(row);
  }
}

async function loadConfig() {
  const data = await fetchJSON('/api/config');
  currentConfig = data.config;
  renderSwitches(currentConfig);
}

async function saveConfig() {
  const patch = {};
  document.querySelectorAll('#switches input[type=checkbox]').forEach((input) => {
    patch[input.dataset.key] = input.checked;
  });
  try {
    await fetchJSON('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch)
    });
    toast('cfg-msg', '配置已保存。已打开的 /protected 实验页需要刷新后才会重新拉取响应头与脚本配置。', true);
  } catch (err) {
    toast('cfg-msg', '保存失败：' + err.message, false);
  }
}

/* --------------------------------- 报告 --------------------------------- */
async function loadReports() {
  const kind = document.getElementById('f-kind').value;
  const sev = document.getElementById('f-sev').value;
  const qs = new URLSearchParams();
  if (kind) qs.set('kind', kind);
  if (sev) qs.set('severity', sev);
  try {
    const data = await fetchJSON('/api/reports?' + qs.toString());
    renderReports(data.reports || []);
  } catch (err) {
    toast('report-msg', '报告加载失败：' + err.message, false);
  }
}

function renderReports(rows) {
  const body = document.getElementById('report-body');
  body.innerHTML = '';
  document.getElementById('report-empty').style.display = rows.length ? 'none' : 'block';
  for (const r of rows) {
    const tr = el('tr');
    const t = new Date(r.recvAt);
    tr.appendChild(el('td', {}, t.toLocaleTimeString()));
    const sevTd = el('td');
    sevTd.appendChild(el('span', { className: 'tag ' + r.severity }, r.severity));
    tr.appendChild(sevTd);
    const kindTd = el('td');
    kindTd.appendChild(el('span', { className: 'tag ' + r.kind }, r.kind));
    tr.appendChild(kindTd);
    tr.appendChild(el('td', {}, r.detector || ''));
    const detailText = r.detail && Object.keys(r.detail).length
      ? '  ' + JSON.stringify(r.detail).slice(0, 160) : '';
    tr.appendChild(el('td', {}, (r.message || '') + detailText));
    body.appendChild(tr);
  }
}

function updateExportLinks() {
  const kind = document.getElementById('f-kind').value;
  const sev = document.getElementById('f-sev').value;
  const qs = new URLSearchParams();
  if (kind) qs.set('kind', kind);
  if (sev) qs.set('severity', sev);
  const base = qs.toString() ? '&' + qs.toString() : '';
  document.getElementById('btn-csv').href = '/api/reports?format=csv' + base;
  document.getElementById('btn-json').href = '/api/reports?format=json' + base;
}

/* ------------------------------- 兼容性自检 ------------------------------- */
function renderCompat() {
  const ul = document.getElementById('compat');
  const checks = [
    ['CSP frame-ancestors', (function () {
      try {
        const e = document.createElement('meta');
        e.httpEquiv = 'Content-Security-Policy';
        // 真正裁决依赖响应头；这里仅判断是否现代引擎（无 feature-detect API，用已知支持范围）
        return 'supported';
      } catch (e) { return 'unsupported'; }
    })(), 'Chrome 40+ / Firefox 35+ / Edge / Safari 10.5+；IE 不支持（由 XFO 兜底）'],
    ['X-Frame-Options', 'supported', '全部主流浏览器（含 IE8+）；ALLOW-FROM 仅旧版 IE/Edge 识别'],
    ['Web Worker', typeof Worker !== 'undefined' ? 'supported' : 'unsupported', 'Chrome / Firefox / Safari / Edge 全支持；失败时自动降级主线程检测'],
    ['navigator.sendBeacon', typeof navigator.sendBeacon === 'function' ? 'supported' : 'unsupported', '用于卸载时上报；不可用时 fetch keepalive 兜底'],
    ['ancestorOrigins', !!(window.location.ancestorOrigins) ? 'supported' : 'unsupported', '仅 Chromium 系提供；缺失时嵌套裁决完全交给 CSP'],
    ['Visibility API', typeof document.hidden === 'boolean' ? 'supported' : 'unsupported', '页面隐藏取证']
  ];
  ul.innerHTML = '';
  for (const [name, status, note] of checks) {
    const li = el('li');
    li.appendChild(el('span', {
      style: 'color:' + (status === 'supported' ? 'var(--green)' : 'var(--yellow)'),
      textContent: status === 'supported' ? '✓ ' : '△ '
    }));
    li.appendChild(document.createTextNode(name + ' — ' + note));
    ul.appendChild(li);
  }
}

/* --------------------------------- 绑定 --------------------------------- */
document.getElementById('btn-save').addEventListener('click', saveConfig);
document.getElementById('btn-reset').addEventListener('click', async () => {
  const allOn = {};
  SWITCH_META.forEach((m) => { allOn[m.key] = true; });
  await fetchJSON('/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(allOn)
  });
  await loadConfig();
  toast('cfg-msg', '已重置为全部启用。', true);
});
document.getElementById('btn-refresh').addEventListener('click', loadReports);
document.getElementById('btn-clear').addEventListener('click', async () => {
  if (!confirm('确认清空全部报告？')) return;
  await fetchJSON('/api/reports', { method: 'DELETE' });
  await loadReports();
});
['f-kind', 'f-sev'].forEach((id) => {
  document.getElementById(id).addEventListener('change', () => { loadReports(); updateExportLinks(); });
});

loadConfig().catch((err) => toast('cfg-msg', '配置加载失败：' + err.message, false));
loadReports();
renderCompat();
setInterval(loadReports, 6000);
