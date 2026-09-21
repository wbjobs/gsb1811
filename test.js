'use strict';

/** 离线测试：用 mock req/res 直接调用 handleRequest，覆盖全部路由与防护头。 */

const assert = require('assert');
const { handleRequest, events } = require('./server');

function mockReq(method, url, body) {
  const listeners = {};
  return {
    method,
    url,
    headers: { host: 'localhost' },
    on(evt, cb) { listeners[evt] = cb; if (evt === 'data' && body) cb(Buffer.from(body)); if (evt === 'end') cb(); },
  };
}

function mockRes() {
  return {
    status: null,
    headers: {},
    body: null,
    writeHead(status, headers) { this.status = status; this.headers = headers; },
    end(payload) { this.body = payload; },
  };
}

async function call(method, url, body) {
  const req = mockReq(method, url, body);
  const res = mockRes();
  await handleRequest(req, res);
  // 静态文件走 fs 回调，等待响应真正写入
  for (let i = 0; i < 100 && res.status === null; i++) {
    await new Promise((r) => setImmediate(r));
  }
  return res;
}

(async () => {
  // 首页与静态资源
  assert.strictEqual((await call('GET', '/')).status, 200, '首页 200');
  assert.strictEqual((await call('GET', '/static/detector-worker.js')).status, 200, 'worker 200');
  assert.strictEqual((await call('GET', '/static/style.css')).status, 200, 'css 200');

  // 路径穿越防护
  const traversal = await call('GET', '/static/../server.js');
  assert.ok([403, 404].includes(traversal.status), '路径穿越被拒绝');

  // 防护头验证
  const cspNone = await call('GET', '/target?defense=csp-none');
  assert.ok(/frame-ancestors 'none'/.test(cspNone.headers['Content-Security-Policy']), 'csp-none 头');
  assert.ok(cspNone.body.includes('var JS_BUSTER_ENABLED = false'), 'csp-none 不启用 JS buster');

  const cspSelf = await call('GET', '/target?defense=csp-self');
  assert.ok(/frame-ancestors 'self'/.test(cspSelf.headers['Content-Security-Policy']), 'csp-self 头');

  const xfo = await call('GET', '/target?defense=xfo');
  assert.strictEqual(xfo.headers['X-Frame-Options'], 'DENY', 'XFO 头');

  const combined = await call('GET', '/target?defense=combined');
  assert.ok(combined.headers['Content-Security-Policy'] && combined.headers['X-Frame-Options'] === 'DENY', '组合防护头');
  assert.ok(combined.body.includes('var JS_BUSTER_ENABLED = true'), '组合防护启用 JS buster');

  const jsBuster = await call('GET', '/target?defense=js-buster');
  assert.ok(jsBuster.body.includes('var JS_BUSTER_ENABLED = true'), 'js-buster 注入');
  assert.ok(!jsBuster.headers['Content-Security-Policy'], 'js-buster 无 CSP 头');

  const none = await call('GET', '/target?defense=none');
  assert.ok(!none.headers['Content-Security-Policy'] && !none.headers['X-Frame-Options'], 'none 无防护头');

  // 攻击页
  assert.strictEqual((await call('GET', '/attack?defense=none&technique=sandbox')).status, 200, 'attack 200');

  // 事件上报与查询
  const before = events.length;
  const evt = await call('POST', '/api/event', JSON.stringify({ type: 'framing-detected', severity: 'high', defense: 'none', detail: 't' }));
  assert.strictEqual(evt.status, 201, '事件上报 201');
  assert.strictEqual(events.length, before + 1, '事件已入列');

  const cspReport = await call('POST', '/api/csp-report', JSON.stringify({ 'csp-report': { 'violated-directive': 'frame-ancestors', 'blocked-uri': 'http://x/' } }));
  assert.strictEqual(cspReport.status, 201, 'CSP 上报 201');
  assert.strictEqual(events[events.length - 1].type, 'csp-violation', 'CSP 事件类型');

  const list = await call('GET', '/api/events');
  assert.strictEqual(list.status, 200, '事件列表 200');
  assert.ok(JSON.parse(list.body).events.length >= 2, '事件列表非空');

  // 报告导出
  const jsonReport = await call('GET', '/api/report?fmt=json');
  assert.strictEqual(jsonReport.status, 200, 'JSON 报告 200');
  assert.ok(/attachment/.test(jsonReport.headers['Content-Disposition']), 'JSON 报告可下载');
  assert.ok(JSON.parse(jsonReport.body).events.length >= 2, 'JSON 报告含事件');

  const htmlReport = await call('GET', '/api/report?fmt=html');
  assert.strictEqual(htmlReport.status, 200, 'HTML 报告 200');
  assert.ok(htmlReport.body.includes('点击劫持防护检测报告'), 'HTML 报告标题');

  // 重置与 404
  assert.strictEqual((await call('POST', '/api/reset')).status, 200, '重置 200');
  assert.strictEqual(events.length, 0, '重置后事件清空');
  assert.strictEqual((await call('GET', '/no-such-route')).status, 404, '未知路由 404');

  console.log('✅ 全部测试通过');
})().catch((err) => { console.error('FAIL:', err.message); process.exit(1); });
