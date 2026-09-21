'use strict';

/**
 * Clickjacking 攻防演练平台（零依赖 Node.js 服务）
 *
 * 路由:
 *   GET  /                  仪表盘
 *   GET  /target?defense=…  被保护的目标页面（按 defense 下发不同防护头）
 *   GET  /attack?…          攻击者页面（iframe 嵌套 + 绕过手法演示）
 *   POST /api/event         检测事件上报（detector.js / CSP report）
 *   GET  /api/events        拉取事件列表
 *   GET  /api/report?fmt=…  导出报告 (json | html)
 *   POST /api/reset         清空事件
 *   GET  /static/*          静态资源
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, 'public');

/** 内存事件存储（演示用途，重启即清空） */
const events = [];
const MAX_EVENTS = 2000;

const DEFENSES = {
  none: {
    label: '无防护',
    headers: {},
    jsBuster: false,
  },
  'csp-none': {
    label: "CSP frame-ancestors 'none'",
    headers: { 'Content-Security-Policy': "frame-ancestors 'none'; report-uri /api/csp-report" },
    jsBuster: false,
  },
  'csp-self': {
    label: "CSP frame-ancestors 'self'",
    headers: { 'Content-Security-Policy': "frame-ancestors 'self'; report-uri /api/csp-report" },
    jsBuster: false,
  },
  xfo: {
    label: 'X-Frame-Options: DENY',
    headers: { 'X-Frame-Options': 'DENY' },
    jsBuster: false,
  },
  'js-buster': {
    label: 'JS 防嵌套 (frame-busting)',
    headers: {},
    jsBuster: true,
  },
  combined: {
    label: '组合防护 (CSP + XFO + JS)',
    headers: {
      'Content-Security-Policy': "frame-ancestors 'none'; report-uri /api/csp-report",
      'X-Frame-Options': 'DENY',
    },
    jsBuster: true,
  },
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && body !== null && !Buffer.isBuffer(body);
  const payload = isObj ? JSON.stringify(body) : body;
  res.writeHead(status, {
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
    'Cache-Control': isObj ? 'no-store' : 'no-store',
    ...headers,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

function pushEvent(evt) {
  const record = {
    id: events.length + 1,
    time: new Date().toISOString(),
    ...evt,
  };
  events.push(record);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  return record;
}

function serveStatic(res, filePath) {
  const rel = path.normalize(filePath).replace(/^(\.\.[/\\])+/, '');
  const abs = path.join(PUBLIC_DIR, rel);
  if (!abs.startsWith(PUBLIC_DIR)) return send(res, 403, 'Forbidden');
  fs.readFile(abs, (err, data) => {
    if (err) return send(res, 404, 'Not Found: ' + rel);
    send(res, 200, data, { 'Content-Type': MIME[path.extname(abs)] || 'application/octet-stream' });
  });
}

function serveTarget(res, defenseKey) {
  const defense = DEFENSES[defenseKey] || DEFENSES.none;
  fs.readFile(path.join(PUBLIC_DIR, 'target.html'), 'utf8', (err, html) => {
    if (err) return send(res, 500, 'target.html missing');
    const injected = html
      .replace('__DEFENSE_KEY__', defenseKey)
      .replace('__DEFENSE_LABEL__', defense.label)
      .replace('__JS_BUSTER__', defense.jsBuster ? 'true' : 'false');
    send(res, 200, injected, defense.headers);
  });
}

function serveAttack(res) {
  fs.readFile(path.join(PUBLIC_DIR, 'attack.html'), 'utf8', (err, html) => {
    if (err) return send(res, 500, 'attack.html missing');
    send(res, 200, html);
  });
}

function buildHtmlReport() {
  const rows = events
    .map(
      (e) =>
        `<tr><td>${e.id}</td><td>${e.time}</td><td>${esc(e.type)}</td>` +
        `<td>${esc(e.defense || '-')}</td><td>${esc(e.technique || '-')}</td>` +
        `<td>${esc(e.severity || '-')}</td><td>${esc(e.detail || '')}</td></tr>`
    )
    .join('\n');
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>点击劫持防护检测报告</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccc;padding:6px 10px;font-size:14px}th{background:#f0f0f0}
h1{font-size:20px}.meta{color:#666;font-size:13px}</style></head><body>
<h1>点击劫持防护检测报告</h1>
<p class="meta">生成时间: ${new Date().toISOString()} · 事件总数: ${events.length}</p>
<table><thead><tr><th>#</th><th>时间</th><th>类型</th><th>防护</th><th>攻击手法</th><th>级别</th><th>详情</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7">暂无事件</td></tr>'}</tbody></table>
</body></html>`;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function handleRequest(req, res) {
  try {
    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (u.pathname === '/') return serveStatic(res, 'index.html');
    if (u.pathname === '/target') return serveTarget(res, u.searchParams.get('defense') || 'none');
    if (u.pathname === '/attack') return serveAttack(res);

    if (u.pathname === '/api/event' && req.method === 'POST') {
      const raw = await readBody(req);
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch { /* 忽略非法 JSON */ }
      return send(res, 201, pushEvent({ type: body.type || 'unknown', ...body }));
    }

    if (u.pathname === '/api/csp-report' && req.method === 'POST') {
      const raw = await readBody(req);
      let report = {};
      try { report = JSON.parse(raw || '{}'); } catch { /* ignore */ }
      const r = report['csp-report'] || report;
      return send(res, 201, pushEvent({
        type: 'csp-violation',
        severity: 'high',
        detail: `CSP 拦截: ${r['violated-directive'] || ''} blocked=${r['blocked-uri'] || ''}`,
      }));
    }

    if (u.pathname === '/api/events') return send(res, 200, { events });

    if (u.pathname === '/api/reset' && req.method === 'POST') {
      events.length = 0;
      return send(res, 200, { ok: true });
    }

    if (u.pathname === '/api/report') {
      const fmt = u.searchParams.get('fmt') || 'json';
      if (fmt === 'html') {
        return send(res, 200, buildHtmlReport(), {
          'Content-Disposition': 'attachment; filename="clickjacking-report.html"',
        });
      }
      return send(res, 200, JSON.stringify({ generatedAt: new Date().toISOString(), events }, null, 2), {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': 'attachment; filename="clickjacking-report.json"',
      });
    }

    if (u.pathname.startsWith('/static/')) return serveStatic(res, u.pathname.slice('/static/'.length));

    send(res, 404, 'Not Found');
  } catch (err) {
    send(res, 500, { error: '服务器内部错误', detail: String(err && err.message) });
  }
}

const server = http.createServer(handleRequest);

server.on('error', (err) => {
  const hints = {
    EADDRINUSE: `端口 ${PORT} 已被占用，请更换 PORT 环境变量`,
    EACCES: `端口 ${PORT} 需要管理员权限，请使用 1024 以上端口`,
    EPERM: '当前环境禁止监听端口（可能处于沙箱中），请在宿主机直接运行',
  };
  console.error(`[clickjacking-lab] 启动失败: ${err.code || err.message}`);
  if (hints[err.code]) console.error(`提示: ${hints[err.code]}`);
  process.exit(1);
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[clickjacking-lab] http://${HOST}:${PORT}`);
  });
}

module.exports = { handleRequest, events, DEFENSES };
