'use strict';

/*
 * UI 欺骗取证 Worker（独立线程）
 * 协议：
 *   main -> worker : {type:'start'} / {type:'sample', seq, ...DOM事实} / {type:'event', kind, ctx}
 *   worker -> main : {type:'ready'} / {type:'probe', seq, t} / {type:'alert', detector, severity, detail}
 * 判定规则全部在 Worker 内完成：攻击者即使在主线程挂调试器冻结脚本，
 * Worker 的独立计时仍会产生“计时器异常”告警。
 */

var INTERVAL = 1000;
var PROBE_TIMEOUT_MS = 2500;
var OVERLAY_CONFIRM = 2; // 连续两次探测到覆盖层才告警，降低误报

var seq = 0;
var expectedTick = 0;
var pendingProbe = null;
var overlayHits = 0;
var lastAlertAt = {};

function throttle(key, cooldownMs) {
  var now = Date.now();
  if (lastAlertAt[key] && now - lastAlertAt[key] < (cooldownMs || 5000)) return false;
  lastAlertAt[key] = now;
  return true;
}

function alert(detector, severity, messageDetail) {
  postMessage({
    type: 'alert',
    detector: detector,
    severity: severity,
    detail: Object.assign({ seq: seq, workerTime: Date.now() }, messageDetail || {})
  });
}

function evaluateSample(sample) {
  // 1) 覆盖层：敏感按钮中心点的最顶层元素不是按钮自身/其子元素
  if (sample.overlay && sample.overlay.blocked) {
    overlayHits += 1;
    if (overlayHits >= OVERLAY_CONFIRM && throttle('overlay', 4000)) {
      alert('overlay', 'critical', { overlay: sample.overlay });
    }
  } else {
    overlayHits = 0;
  }

  // 2) 原生 API 完整性
  if (sample.nativesOk === false && throttle('tamper', 4000)) {
    alert('tamper', 'critical', { failed: sample.nativeChecksFailed || [] });
  }

  // 3) 持续隐藏状态只记录低级别；“隐藏中交互”由事件规则升级
  if (sample.hidden) hiddenTicks += 1; else hiddenTicks = 0;
}
var hiddenTicks = 0;

function evaluateEvent(ev) {
  var ctx = ev.ctx || {};
  if (ev.kind === 'click') {
    // 隐藏页面中发生点击：合成点击 / 隐藏 iframe 劫持
    if (ctx.hidden && throttle('hidden-click')) {
      alert('hidden', 'critical', { reason: 'document.hidden=true 时发生点击' });
    }
    // 点击前长时间失焦：用户的鼠标事件不在本窗口，典型透明覆盖劫持
    if (ctx.blurredMs > 3000 && throttle('blur-click')) {
      alert('blur', 'critical', { reason: '点击前窗口失焦 ' + ctx.blurredMs + 'ms' });
    }
    // 点击前 1.5s 内本窗口无鼠标移动：要么合成点击，要么点击来自顶层覆盖
    if (ctx.sinceMouseMoveMs > 1500 && !ctx.trustedUserGesture && throttle('nomove-click', 6000)) {
      alert('blur', 'warning', {
        reason: '点击前 ' + ctx.sinceMouseMoveMs + 'ms 内无鼠标移动，疑似诱导/合成点击'
      });
    }
  }
  if (ev.kind === 'visibility') {
    if (ctx.hidden && throttle('hidden', 10000)) {
      alert('hidden', 'info', { reason: '页面转入隐藏状态（记录基线）' });
    }
  }
}

function tick() {
  var now = Date.now();

  // 4) Worker 自身计时器漂移：标签页被挂起/调试器冻结后会一次性出现大间隔
  if (expectedTick && now - expectedTick > PROBE_TIMEOUT_MS) {
    if (throttle('timer-drift', 4000)) {
      alert('timer', 'critical', {
        reason: 'Worker 计时器间隔异常',
        expected: INTERVAL,
        actual: now - expectedTick
      });
    }
  }
  expectedTick = now + INTERVAL;

  // 5) 主线程探测应答超时（主线程被长任务/调试器阻塞）
  if (pendingProbe && now - pendingProbe.sentAt > PROBE_TIMEOUT_MS) {
    if (throttle('probe-timeout', 4000)) {
      alert('timer', 'warning', {
        reason: '主线程探测应答超时',
        seq: pendingProbe.seq,
        delay: now - pendingProbe.sentAt
      });
    }
    pendingProbe = null;
  }

  seq += 1;
  pendingProbe = { seq: seq, sentAt: now };
  postMessage({ type: 'probe', seq: seq, t: now });
}

onmessage = function (e) {
  var msg = e.data || {};
  if (msg.type === 'start') {
    postMessage({ type: 'ready', interval: INTERVAL });
    expectedTick = Date.now() + INTERVAL;
    setInterval(tick, INTERVAL);
    return;
  }
  if (msg.type === 'sample') {
    if (pendingProbe && msg.seq === pendingProbe.seq) {
      var delay = Date.now() - pendingProbe.sentAt;
      if (delay > PROBE_TIMEOUT_MS && throttle('sample-delay', 4000)) {
        alert('timer', 'warning', { reason: '主线程应答延迟', delay: delay });
      }
      pendingProbe = null;
    }
    evaluateSample(msg);
    return;
  }
  if (msg.type === 'event') {
    evaluateEvent(msg);
  }
};
