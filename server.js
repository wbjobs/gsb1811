'use strict';

/*
 * frame-defense-lab
 * 三个来源（用端口模拟，无需 hosts/DNS）：
 *   :8080 受保护站点（受防护页面、控制台、报告收集）
 *   :9001 攻击者站点（点击劫持 / 嵌套演示）
 *   :9002 可信合作方（allowlist 白名单演示）
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT_DEFENDER = Number(process.env.PORT_DEFENDER || 8080);
const PORT_ATTACKER = Number(process.env.PORT_ATTACKER || 9001);
const PORT_PARTNER = Number(process.env.PORT_PARTNER || 9002);

const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_REPORTS = 2000;

/* ----------------------------- 防护配置（内存态） ----------------------------- */
// 默认全开，体现纵深防御；可在控制台实时切换后重试“绕过演示”。
const config = {
  cspFrameAncestors: true,   // 现代浏览器主防线：Content-Security-Policy: frame-ancestors
  cspReportOnly: false,      // true 时仅上报不拦截（演练 / 灰度模式）
  xFrameOptions: true,       // 旧浏览器兜底：X-Frame-Options
  jsFrameBust: true,         // JS 防嵌套：顶层窗口自检 + 逃生跳转
  workerMonitor: true,       // Web Worker 监测：隐藏/失焦/透明覆盖/计时器异常等
  allowPartner: true,        // 白名单：允许可信合作方嵌套
  ancestors: [
    `http://localhost:${PORT_DEFENDER}`,
    `http://127.0.0.1:${PORT_DEFENDER}`,
    `http://localhost:${PORT_PARTNER}`,
    `http://127.0.0.1:${PORT_PARTNER}`
  ]
};

/* --------------------------------- 报告存储 --------------------------------- */
const reports = [];
let reportSeq = 0;

function addReport(entry) {
  reportSeq += 1;
  const record = Object.assign(
    { id: reportSeq, recvAt: new Date().toISOString() },
    entry
  );
  reports.unshift(record);
  if (reports.length > MAX_REPORTS) reports.length = MAX_REPORTS;
  return record;
}

function csvCell(value) {
  const text = value === null || value === undefined ? '' : String(value);
  if (/[",\n\r]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
  return text;
}

function toCSV(rows) {
  const header = ['id', 'recvAt', 'kind', 'severity', 'source', 'detector', 'message', 'detail', 'ua'];
  const lines = [header.join(',')];
  for (const row of rows) {
    lines.push([
      row.id,
      row.recvAt,
      row.kind,
      row.severity,
      row.source,
      row.detector,
      row.message,
      typeof row.detail === 'string' ? row.detail : JSON.stringify(row.detail || {}),
      row.ua
    ].map(csvCell).join(','));
  }
  return lines.join('\r\n');
}

/* --------------------------------- HTTP 工具 -------------------------------- */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
};

function sendJSON(res, status, payload, extraHeaders) {
  const body = JSON.stringify(payload);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  }, extraHeaders || {}));
  res.end(body);
}

function sendError(res, status, message) {
  sendJSON(res, status, { error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error('请求体过大（上限 1MB）'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function serveStatic(req, res, baseDir, urlPath) {
  const rel = urlPath.split('?')[0];
  const filePath = path.normalize(path.join(baseDir, rel));
  if (!filePath.startsWith(baseDir)) {
    sendError(res, 403, '非法路径');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      sendError(res, 404, `文件不存在: ${rel}`);
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    res.end(data);
  });
}

/* ------------------------- 受保护页面：动态防护响应头 ------------------------- */
function buildFrameAncestors() {
  const list = config.allowPartner
    ? config.ancestors
    : config.ancestors.filter((origin) =>
        !origin.endsWith(':' + PORT_PARTNER));
  return ["'self'"].concat(list).join(' ');
}

function serveProtectedPage(req, res) {
  const filePath = path.join(PUBLIC_DIR, 'protected.html');
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) {
      sendError(res, 500, '受保护页面缺失');
      return;
    }
    const clientConfig = {
      jsFrameBust: config.jsFrameBust,
      workerMonitor: config.workerMonitor
    };
    const rendered = html
      .replace(/__CONFIG__/g, JSON.stringify(clientConfig))
      .replace(/__REPORT_ENDPOINT__/g, '/api/report');

    const headers = {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store'
    };
    if (config.cspFrameAncestors) {
      const directive = 'frame-ancestors ' + buildFrameAncestors();
      const headerName = config.cspReportOnly
        ? 'Content-Security-Policy-Report-Only'
        : 'Content-Security-Policy';
      headers[headerName] = directive + '; report-uri /api/csp-report';
    }
    if (config.xFrameOptions) {
      // 与 frame-ancestors 白名单保持一致：合作方在白名单内时用 ALLOW-FROM（旧浏览器），
      // 否则 DENY（最严格，同时兼容所有支持 XFO 的旧浏览器）。
      headers['X-Frame-Options'] = config.allowPartner
        ? `ALLOW-FROM http://localhost:${PORT_PARTNER}`
        : 'DENY';
    }
    res.writeHead(200, headers);
    res.end(rendered);
  });
}

/* --------------------------------- 路由 ----------------------------------- */
function createDefenderServer() {
  return http.createServer((req, res) => {
    handleDefender(req, res).catch((err) => {
      console.error('请求处理异常:', err);
      if (!res.headersSent) sendError(res, 500, '服务器内部异常：' + err.message);
    });
  });
}

async function handleDefender(req, res) {
  const url = req.url.split('?')[0];

  // 报告接收（JS / Worker 上报 + CSP 违规上报，同一入口）
  if (url === '/api/report' || url === '/api/csp-report') {
    if (req.method !== 'POST') {
      res.writeHead(204);
      res.end();
      return;
    }
    let parsed = null;
    try {
      const raw = await readBody(req);
      parsed = raw ? JSON.parse(raw) : {};
    } catch (err) {
      sendError(res, 400, '报告 JSON 解析失败：' + err.message);
      return;
    }
    try {
      const base = {
        ua: req.headers['user-agent'] || '',
        ip: req.socket.remoteAddress || ''
      };
      if (parsed['csp-report']) {
        // Content-Security-Policy violation report 结构
        const csp = parsed['csp-report'];
        addReport(Object.assign(base, {
          kind: 'csp',
          severity: config.cspReportOnly ? 'warning' : 'critical',
          source: csp['document-uri'] || '',
          detector: 'frame-ancestors',
          message: config.cspReportOnly
            ? 'CSP 演练模式(Report-Only)记录到非法嵌套'
            : 'CSP frame-ancestors 拦截非法嵌套',
          detail: {
            violatedDirective: csp['violated-directive'] || '',
            blockedURI: csp['blocked-uri'] || '',
            disposition: csp['disposition'] || (config.cspReportOnly ? 'report' : 'enforce')
          }
        }));
      } else {
        addReport(Object.assign(base, {
          kind: String(parsed.kind || 'client'),
          severity: ['info', 'warning', 'critical'].includes(parsed.severity) ? parsed.severity : 'info',
          source: String(parsed.source || ''),
          detector: String(parsed.detector || ''),
          message: String(parsed.message || '客户端事件'),
          detail: parsed.detail && typeof parsed.detail === 'object' ? parsed.detail : {}
        }));
      }
    } catch (err) {
      sendError(res, 500, '报告入库失败：' + err.message);
      return;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  // 防护配置查询 / 更新（控制台使用）
  if (url === '/api/config') {
    if (req.method === 'GET') {
      sendJSON(res, 200, { config, ports: { defender: PORT_DEFENDER, attacker: PORT_ATTACKER, partner: PORT_PARTNER } });
      return;
    }
    if (req.method === 'POST') {
      try {
        const raw = await readBody(req);
        const patch = JSON.parse(raw || '{}');
        const boolKeys = ['cspFrameAncestors', 'cspReportOnly', 'xFrameOptions', 'jsFrameBust', 'workerMonitor', 'allowPartner'];
        for (const key of boolKeys) {
          if (key in patch) {
            if (typeof patch[key] !== 'boolean') throw new Error(`${key} 必须为布尔值`);
            config[key] = patch[key];
          }
        }
        addReport({
          kind: 'admin',
          severity: 'info',
          source: 'dashboard',
          detector: 'config',
          message: '防护配置已更新',
          detail: patch,
          ua: req.headers['user-agent'] || ''
        });
        sendJSON(res, 200, { ok: true, config });
      } catch (err) {
        sendError(res, 400, err.message);
      }
      return;
    }
    sendError(res, 405, '仅支持 GET/POST');
    return;
  }

  // 报告查询 / 导出
  if (url === '/api/reports') {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const kind = params.get('kind');
    const severity = params.get('severity');
    let rows = reports;
    if (kind) rows = rows.filter((r) => r.kind === kind);
    if (severity) rows = rows.filter((r) => r.severity === severity);

    if (req.method === 'DELETE') {
      reports.length = 0;
      sendJSON(res, 200, { ok: true, cleared: true });
      return;
    }
    if (req.method !== 'GET') {
      sendError(res, 405, '仅支持 GET/DELETE');
      return;
    }
    const format = params.get('format');
    if (format === 'csv') {
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="frame-defense-reports.csv"',
        'Cache-Control': 'no-store'
      });
      res.end(toCSV(rows));
      return;
    }
    if (format === 'json') {
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': 'attachment; filename="frame-defense-reports.json"',
        'Cache-Control': 'no-store'
      });
      res.end(JSON.stringify({ exportedAt: new Date().toISOString(), count: rows.length, reports: rows }, null, 2));
      return;
    }
    sendJSON(res, 200, { total: rows.length, reports: rows.slice(0, 300) });
    return;
  }

  // 页面路由
  if (url === '/' || url === '/index.html') return serveStatic(req, res, PUBLIC_DIR, '/index.html');
  if (url === '/protected') return serveProtectedPage(req, res);
  if (url.startsWith('/public/') || url === '/app.js' || url === '/protected.js' || url === '/monitor.worker.js') {
    return serveStatic(req, res, PUBLIC_DIR, url === '/app.js' ? '/app.js' : url.replace(/^\/public/, ''));
  }
  sendError(res, 404, '未找到路由: ' + url);
}

function makeSimpleServer(baseDir) {
  return http.createServer((req, res) => {
    // 静态站点根：/ -> /index.html
    let rel = req.url.split('?')[0];
    if (rel === '/') rel = '/index.html';
    serveStatic(req, res, baseDir, rel);
  });
}

/* --------------------------------- 启动 ----------------------------------- */
function start(server, port, name) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, () => {
      console.log(`[frame-defense-lab] ${name} http://localhost:${port}`);
      resolve();
    });
  });
}

if (process.env.FRAME_LAB_NO_LISTEN !== '1') {
(async () => {
  try {
    await start(createDefenderServer(), PORT_DEFENDER, '受保护站点/控制台');
    await start(makeSimpleServer(path.join(PUBLIC_DIR, 'attacker')), PORT_ATTACKER, '攻击者站点');
    await start(makeSimpleServer(path.join(PUBLIC_DIR, 'partner')), PORT_PARTNER, '可信合作方');
  } catch (err) {
    console.error('启动失败：', err.message);
    process.exit(1);
  }
})();
}

module.exports = {
  config, addReport, toCSV,
  createDefenderServer, makeSimpleServer,
  getReports: () => reports, clearReports: () => { reports.length = 0; },
  resetConfig: () => {
    Object.assign(config, {
      cspFrameAncestors: true, cspReportOnly: false, xFrameOptions: true,
      jsFrameBust: true, workerMonitor: true, allowPartner: true
    });
  }
};
