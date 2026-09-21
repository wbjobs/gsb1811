'use strict';

/*
 * 零依赖冒烟测试（内存级 mock req/res，无需监听端口，CI/沙箱均可运行）：
 * 验证防护头、配置开关、报告收发/过滤/导出、异常状态码与静态站点。
 */

const assert = require('assert');
const path = require('path');

process.env.PORT_DEFENDER = '8080';
process.env.PORT_ATTACKER = '9001';
process.env.PORT_PARTNER = '9002';

// require 即可能执行启动 IIFE，需先阻止 listen：注入一个会抛错的 http 模块钩子太重，
// 因此服务器启动段检测环境变量 FRAME_LAB_NO_LISTEN。
process.env.FRAME_LAB_NO_LISTEN = '1';
const srv = require(path.join(__dirname, '..', 'server.js'));

let passed = 0;
function ok(name) { passed += 1; console.log('  ✓ ' + name); }

const { EventEmitter } = require('events');

function makeReq(method, urlPath, bodyText) {
  const req = new EventEmitter();
  req.method = method;
  req.url = urlPath;
  req.headers = { 'user-agent': 'smoke-test/1.0' };
  req.socket = { remoteAddress: '127.0.0.1' };
  req.destroy = function () { this._destroyed = true; };
  setImmediate(() => {
    if (bodyText) req.emit('data', Buffer.from(bodyText));
    req.emit('end');
  });
  return req;
}

function makeRes() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    headersSent: false,
    ended: false,
    writeHead(status, headers) {
      this.statusCode = status;
      for (const [k, v] of Object.entries(headers || {})) this.headers[k.toLowerCase()] = v;
      this.headersSent = true;
    },
    write(chunk) { this.body += chunk.toString(); },
    end(chunk) { if (chunk) this.body += chunk.toString(); this.ended = true; }
  };
}

function call(method, urlPath, bodyText) {
  return new Promise((resolve, reject) => {
    const server = srv.createDefenderServer();
    const req = makeReq(method, urlPath, bodyText);
    const res = makeRes();
    const origEnd = res.end.bind(res);
    res.end = (chunk) => { origEnd(chunk); resolve(res); };
    server.emit('request', req, res);
  });
}

(async () => {
  try {
    srv.resetConfig();
    srv.clearReports();

    // 1) 默认防护头
    let res = await call('GET', '/protected');
    assert.strictEqual(res.statusCode, 200);
    const csp = res.headers['content-security-policy'] || '';
    assert.ok(csp.includes("frame-ancestors 'self'"), csp);
    assert.ok(csp.includes('localhost:9002'));
    assert.ok(csp.includes('report-uri'));
    assert.strictEqual(res.headers['x-frame-options'], 'ALLOW-FROM http://localhost:9002');
    assert.ok(res.body.includes('"jsFrameBust":true'));
    assert.ok(res.body.includes('/api/report'));
    ok('默认配置：frame-ancestors + XFO + 客户端配置注入');

    // 2) 白名单开关
    res = await call('POST', '/api/config', JSON.stringify({ allowPartner: false }));
    assert.strictEqual(res.statusCode, 200);
    res = await call('GET', '/protected');
    assert.ok(!(res.headers['content-security-policy'] || '').includes('localhost:9002'));
    assert.strictEqual(res.headers['x-frame-options'], 'DENY');
    ok('关闭白名单：合作方来源移除，XFO=DENY');

    // 3) 关闭头部防护（绕过实验前置）
    res = await call('POST', '/api/config', JSON.stringify({ cspFrameAncestors: false, xFrameOptions: false }));
    res = await call('GET', '/protected');
    assert.ok(!res.headers['content-security-policy']);
    assert.ok(!res.headers['x-frame-options']);
    ok('关闭 CSP/XFO：响应头无防护字段，用于可复现绕过');

    // 4) Report-Only
    res = await call('POST', '/api/config', JSON.stringify({ cspFrameAncestors: true, cspReportOnly: true }));
    res = await call('GET', '/protected');
    assert.ok(res.headers['content-security-policy-report-only']);
    assert.ok(!res.headers['content-security-policy']);
    ok('演练模式：仅下发 Report-Only 头');

    // 5) 恢复默认 + JS 上报
    srv.resetConfig();
    res = await call('POST', '/api/report', JSON.stringify({
      kind: 'framing', severity: 'critical', source: 'http://localhost:9001/',
      detector: 'js-framebust', message: '顶层跳转被阻止'
    }));
    assert.strictEqual(res.statusCode, 204);
    res = await call('GET', '/api/reports?kind=framing');
    let rows = JSON.parse(res.body);
    assert.ok(rows.total >= 1 && rows.reports[0].detector === 'js-framebust');
    ok('JS/Worker 事件上报入库并可按类型查询');

    // 6) CSP 违规报告归一化
    res = await call('POST', '/api/csp-report', JSON.stringify({
      'csp-report': {
        'document-uri': 'http://localhost:8080/protected',
        'violated-directive': 'frame-ancestors',
        'blocked-uri': 'http://evil.example'
      }
    }));
    assert.strictEqual(res.statusCode, 204);
    res = await call('GET', '/api/reports?kind=csp');
    rows = JSON.parse(res.body);
    assert.ok(rows.total >= 1 && rows.reports[0].detector === 'frame-ancestors');
    assert.strictEqual(rows.reports[0].kind, 'csp');
    ok('CSP violation report 归一化为 csp/frame-ancestors');

    // 7) 过滤与导出
    res = await call('GET', '/api/reports?kind=csp&format=csv');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('text/csv'));
    assert.ok(res.body.startsWith('id,recvAt,kind,severity'));
    assert.ok(res.body.includes('frame-ancestors'));
    // CSV 特殊字符转义
    srv.addReport({ kind: 'x', severity: 'info', source: '', detector: 'd', message: '含,逗号"引号', detail: {}, ua: '' });
    res = await call('GET', '/api/reports?kind=x&format=csv');
    assert.ok(res.body.includes('"含,逗号""引号"'));
    res = await call('GET', '/api/reports?format=json');
    const exported = JSON.parse(res.body);
    assert.ok(Array.isArray(exported.reports) && exported.count === exported.reports.length);
    ok('报告导出 CSV（含转义）/ JSON，支持过滤参数');

    // 8) 异常提示
    res = await call('POST', '/api/report', '{bad-json');
    assert.strictEqual(res.statusCode, 400);
    assert.ok(JSON.parse(res.body).error.includes('JSON'));
    res = await call('POST', '/api/config', JSON.stringify({ jsFrameBust: 'yes' }));
    assert.strictEqual(res.statusCode, 400);
    assert.ok(JSON.parse(res.body).error.includes('布尔'));
    res = await call('GET', '/api/no-such-route');
    assert.strictEqual(res.statusCode, 404);
    res = await call('PUT', '/api/reports');
    assert.strictEqual(res.statusCode, 405);
    ok('坏 JSON / 非法参数 / 404 / 405 均有 JSON 错误提示');

    // 9) 静态页面与 Worker
    res = await call('GET', '/');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.includes('防嵌套防护实验室'));
    res = await call('GET', '/monitor.worker.js');
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('javascript'));
    res = await call('GET', '/../package.json');
    assert.ok(res.statusCode === 403 || res.statusCode === 404);
    ok('控制台/Worker 正常服务，路径穿越被拒');

    // 10) 清空
    res = await call('DELETE', '/api/reports');
    assert.strictEqual(res.statusCode, 200);
    res = await call('GET', '/api/reports');
    assert.strictEqual(JSON.parse(res.body).total, 0);
    ok('报告清空');

    // 11) 静态攻击者/合作方站点工厂不报错地存在（直接读文件验证内容）
    const fs = require('fs');
    const attackerPage = fs.readFileSync(path.join(__dirname, '..', 'public', 'attacker', 'index.html'), 'utf8');
    assert.ok(attackerPage.includes('victim-frame'));
    const sandboxPage = fs.readFileSync(path.join(__dirname, '..', 'public', 'attacker', 'sandbox.html'), 'utf8');
    assert.ok(sandboxPage.includes('allow-top-navigation'));
    const partnerPage = fs.readFileSync(path.join(__dirname, '..', 'public', 'partner', 'index.html'), 'utf8');
    assert.ok(partnerPage.includes('白名单'));
    ok('攻击者三类实验页与合作方页面齐备');

    console.log('\n全部通过：' + passed + ' 项断言 ✓');
  } catch (err) {
    console.error('\n测试失败：', err.stack || err.message);
    process.exitCode = 1;
  }
})();
