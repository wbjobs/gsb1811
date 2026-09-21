'use strict';

/*
 * 受保护页面脚本：JS 防嵌套 + Web Worker 监测桥接 + 异常提示。
 * 设计要点：
 *  - 每一步都 try/catch 包裹，攻击者可禁用 JS、可 try 重写 top.location，
 *    因此 JS 防线只是 frame-ancestors/XFO 的补充（纵深防御），单独依赖它必被绕过——
 *    这正是实验要展示的结论。
 *  - Worker 承担周期性取证；即使主线程被 debugger/长任务阻塞，
 *    Worker 心跳超时本身也构成一条“计时器异常”告警。
 */

(function () {
  const cfg = window.__DEFENSE_CONFIG__ || {};
  const REPORT_URL = window.__REPORT_ENDPOINT__ || '/api/report';

  const $status = document.getElementById('status');
  const $log = document.getElementById('log');
  const $banner = document.getElementById('defense-banner');
  const $bannerTitle = document.getElementById('banner-title');
  const $bannerText = document.getElementById('banner-text');
  const $escape = document.getElementById('banner-escape');

  const state = {
    framed: false,
    ancestorOrigins: [],
    workerOk: null,
    blocked: false
  };

  function log(line, level) {
    const time = new Date().toLocaleTimeString();
    const mark = level === 'critical' ? '‼' : level === 'warning' ? '!' : '·';
    $log.textContent = `[${time}] ${mark} ${line}\n` + $log.textContent;
  }

  function report(kind, severity, detector, message, detail) {
    const payload = {
      kind: kind,
      severity: severity,
      source: location.href,
      detector: detector,
      message: message,
      detail: detail || {},
      ts: Date.now()
    };
    // sendBeacon 优先（页面卸载/跳转时也尽量送达），fetch 兜底
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(REPORT_URL, new Blob([JSON.stringify(payload)], { type: 'application/json' }));
        return;
      }
    } catch (err) { /* fallthrough */ }
    try {
      fetch(REPORT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true,
        credentials: 'include'
      }).catch(function () { /* 报告失败不阻断业务，本地仍有日志 */ });
    } catch (err) { /* 离线/极端环境，静默降级 */ }
  }

  function renderPill(key, on, labelOn, labelOff) {
    let el = document.querySelector('[data-pill="' + key + '"]');
    if (!el) {
      el = document.createElement('span');
      el.className = 'pill';
      el.setAttribute('data-pill', key);
      $status.appendChild(el);
    }
    el.textContent = on ? labelOn : labelOff;
    el.classList.toggle('on', !!on);
    el.classList.toggle('off', !on);
  }

  function showBanner(title, text, critical) {
    state.blocked = true;
    $bannerTitle.textContent = title;
    $bannerText.textContent = text;
    $banner.classList.add('show');
    $banner.style.background = critical ? 'rgba(207,34,46,.96)' : 'rgba(154,103,0,.95)';
    document.body.classList.add('is-blocked');
  }

  $escape.addEventListener('click', function () {
    try { window.open(location.href, '_blank', 'noopener'); }
    catch (err) { report('error', 'warning', 'escape', '弹窗被浏览器拦截', { error: String(err) }); }
  });

  /* --------------------------- 1) JS 防嵌套自检 --------------------------- */
  function detectFraming() {
    let framed = false;
    try {
      // window.top 跨域访问在现代浏览器返回 null（不会抛错）；
      // self !== top 是最通用的“是否被嵌套”信号。
      framed = window.top !== window.self;
    } catch (err) {
      // 访问 window.top 抛异常（极端旧环境/沙箱）同样意味着处于嵌套结构中
      framed = true;
    }
    state.framed = framed;
    document.body.classList.toggle('is-framed', framed);

    const origins = [];
    try {
      if (window.location.ancestorOrigins && window.location.ancestorOrigins.length) {
        for (let i = 0; i < window.location.ancestorOrigins.length; i++) {
          origins.push(window.location.ancestorOrigins[i]);
        }
      }
    } catch (err) { /* ancestorOrigins 仅 Chromium 系支持，其它浏览器不可用属正常 */ }
    state.ancestorOrigins = origins;
    return { framed: framed, ancestorOrigins: origins };
  }

  function frameBust() {
    const info = detectFraming();
    renderPill('framed', !info.framed, '顶层窗口运行', '正被 iframe 嵌套');

    if (!info.framed) {
      log('页面运行在顶层窗口，环境正常。');
      return;
    }

    // 白名单核验（合作方来源）。ancestorOrigins 不可用时退化为“嵌套即告警”，
    // 由 CSP frame-ancestors 做最终授权裁决，避免误伤。
    const partnerOrigin = location.protocol + '//' + location.host.replace(/:8080$/, ':9002');
    const selfOrigin = location.origin;
    const allowed = info.ancestorOrigins.length
      ? info.ancestorOrigins.every(function (o) { return o === selfOrigin || o === partnerOrigin; })
      : null; // null = 无法判断（Firefox/Safari 无 ancestorOrigins）

    log('检测到 iframe 嵌套；祖先来源: ' + (info.ancestorOrigins.join(' , ') || '无法读取（浏览器不支持 ancestorOrigins）'), 'warning');
    report('framing', allowed === false ? 'critical' : 'warning', 'js-framebust',
      allowed === false ? '检测到非白名单来源嵌套' : '检测到嵌套，等待 CSP/XFO 授权裁决',
      { ancestorOrigins: info.ancestorOrigins, determinable: allowed !== null });

    if (allowed === false) {
      // 逃生跳转：覆盖 UI 阻断点击劫持，并尝试顶层替换
      showBanner('检测到页面被非法嵌套', '该页面正被未知站点嵌入，存在点击劫持风险，内容已被遮挡。', true);
      try {
        // 经典 frame-busting；攻击者可用 sandbox="allow-scripts"（不给 allow-top-navigation）使其抛错——
        // 抛错也会被记录为一次“绕过成功”的证据。
        window.top.location = location.href;
      } catch (err) {
        log('顶层跳转被阻止（典型的 sandbox 绕过）：' + err.name, 'critical');
        report('framing', 'critical', 'js-framebust', '顶层跳转被阻止，frame-busting 被绕过',
          { error: String(err && err.name || err) });
      }
    }
  }

  /* --------------------------- 2) Web Worker 监测 -------------------------- */
  let worker = null;
  let heartbeatTimer = null;
  let lastBeat = 0;
  let stalls = 0;

  function startWorkerMonitor() {
    renderPill('worker', false, 'Worker 监测启用中…', 'Worker 监测已关闭');
    try {
      worker = new Worker('/monitor.worker.js');
      worker.postMessage({ type: 'start' });
    } catch (err) {
      state.workerOk = false;
      renderPill('worker', false, 'Worker 不可用', 'Worker 监测已关闭');
      const pill = document.querySelector('[data-pill="worker"]');
      pill.classList.remove('on', 'off');
      pill.classList.add('err');
      log('Web Worker 不可用，UI 欺骗检测降级：' + err.message, 'warning');
      report('error', 'warning', 'worker', 'Web Worker 创建失败，降级为纯主线程检测', { error: String(err) });
      startMainThreadFallback();
      return;
    }

    worker.onmessage = function (ev) {
      const msg = ev.data || {};
      lastBeat = Date.now();

      if (msg.type === 'ready') {
        state.workerOk = true;
        renderPill('worker', true, 'Worker 监测运行中', 'Worker 监测已关闭');
        log('Web Worker 监测已启动（周期 ' + msg.interval + 'ms）。');
        installInteractionProbes(worker);
      } else if (msg.type === 'probe') {
        try { worker.postMessage(Object.assign({ type: 'sample', seq: msg.seq }, collectDOMFacts())); }
        catch (err) { report('error', 'warning', 'worker', 'DOM 取证失败', { error: String(err) }); }
      } else if (msg.type === 'alert') {
        handleAlert(msg);
      }
    };
    worker.onerror = function (err) {
      state.workerOk = false;
      log('Worker 运行错误：' + (err.message || '未知错误'), 'warning');
      report('error', 'warning', 'worker', 'Worker 运行错误', { error: String(err.message || err) });
    };

    lastBeat = Date.now();
    heartbeatTimer = setInterval(function () {
      const gap = Date.now() - lastBeat;
      if (gap > 4000) {
        stalls += 1;
        log('Worker 心跳超时 ' + gap + 'ms（主线程被阻塞或 Worker 被挂起）', stalls >= 3 ? 'critical' : 'warning');
        if (stalls >= 3) {
          report('uitamper', 'critical', 'worker-heartbeat', 'Worker 心跳连续超时，疑似调试器冻结/挂起', { gap: gap, stalls: stalls });
          stalls = 0;
        }
      }
    }, 2000);
  }

  // Worker 不可用时的降级检测（主线程版，功能子集）
  let fallbackTimers = [];
  function startMainThreadFallback() {
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        report('uitamper', 'warning', 'visibility-fallback', '页面被隐藏（降级检测）', { visibilityState: document.visibilityState });
      }
    });
    let last = Date.now();
    fallbackTimers.push(setInterval(function () {
      const drift = Date.now() - last - 1000;
      last = Date.now();
      if (drift > 2500) report('uitamper', 'warning', 'timer-fallback', '主线程计时器严重漂移（降级检测）', { drift: drift });
    }, 1000));
  }

  /* ----------------------- 主线程取证（供 Worker 判定） ---------------------- */
  let lastMouseMoveAt = Date.now();
  let blurSince = 0;

  function collectDOMFacts() {
    const facts = { hidden: document.hidden, overlay: null, nativesOk: true, nativeChecksFailed: [] };
    try {
      const btn = document.getElementById('pay-btn');
      if (btn) {
        const rect = btn.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const topEl = document.elementFromPoint(cx, cy);
        const blocked = !!(topEl && topEl !== btn && !btn.contains(topEl));
        if (blocked) {
          const style = window.getComputedStyle(topEl);
          facts.overlay = {
            blocked: true,
            topTag: topEl.tagName,
            topId: topEl.id || '',
            topClass: (topEl.className && topEl.className.toString().slice(0, 80)) || '',
            opacity: style.opacity,
            zIndex: style.zIndex
          };
        } else {
          facts.overlay = { blocked: false };
        }
      }
    } catch (err) {
      facts.overlay = { blocked: false, error: String(err) };
    }
    // 关键原生 API 完整性：toString 被改写通常意味着防护被 hook
    const checks = [
      [window, 'open'], [window, 'addEventListener'], [document, 'createElement'],
      [Element.prototype, 'getBoundingClientRect'], [document, 'elementFromPoint']
    ];
    for (const pair of checks) {
      try {
        const fn = pair[0] && pair[0][pair[1]];
        if (typeof fn !== 'function' || !/\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn))) {
          facts.nativeChecksFailed.push(pair[1]);
        }
      } catch (err) {
        facts.nativeChecksFailed.push(pair[1] + ':err');
      }
    }
    facts.nativesOk = facts.nativeChecksFailed.length === 0;
    return facts;
  }

  function installInteractionProbes(workerRef) {
    document.addEventListener('mousemove', function () { lastMouseMoveAt = Date.now(); }, true);
    window.addEventListener('blur', function () { blurSince = Date.now(); }, true);
    window.addEventListener('focus', function () { blurSince = 0; }, true);
    document.addEventListener('visibilitychange', function () {
      workerRef.postMessage({ type: 'event', kind: 'visibility', ctx: { hidden: document.hidden } });
    }, true);
    document.addEventListener('click', function (ev) {
      const now = Date.now();
      workerRef.postMessage({
        type: 'event',
        kind: 'click',
        ctx: {
          hidden: document.hidden,
          blurredMs: blurSince ? now - blurSince : 0,
          sinceMouseMoveMs: now - lastMouseMoveAt,
          trusted: !!ev.isTrusted,
          target: ev.target && ev.target.id || (ev.target && ev.target.tagName)
        }
      });
    }, true);
  }

  function handleAlert(msg) {
    const map = {
      hidden: ['页面被隐藏后仍发生交互', '恶意页面可能在隐藏 iframe 中诱导操作'],
      blur: ['窗口长时间失焦后突发点击', '可能存在透明覆盖层点击劫持'],
      overlay: ['检测到可疑覆盖层/透明 iframe', 'document.elementFromPoint 发现交互点被未知元素遮挡'],
      timer: ['检测到计时器异常', '事件循环被冻结或标签页被挂起，存在取证对抗嫌疑'],
      tamper: ['检测到防护 API 被改写', '防嵌套关键函数被外部脚本篡改']
    };
    const meta = map[msg.detector] || ['可疑 UI 欺骗信号', '详见报告'];
    const level = msg.severity === 'critical' ? 'critical' : 'warning';
    log(meta[0] + '（' + msg.detector + '）', level);
    report('uitamper', msg.severity || 'warning', msg.detector, meta[1], msg.detail || {});

    if (msg.severity === 'critical' && !state.blocked) {
      showBanner('检测到疑似 UI 欺骗攻击', meta[1] + '。为保护账户安全，操作已暂停。', true);
    }
  }

  /* --------------------------- 3) 业务按钮（蜜罐点击） -------------------------- */
  document.getElementById('pay-btn').addEventListener('click', function () {
    const inFrame = state.framed;
    const docHidden = document.hidden;
    const result = document.getElementById('pay-result');
    if (inFrame || docHidden) {
      result.textContent = '⚠ 本次点击发生在嵌套/隐藏环境中，已拦截并上报，未执行转账。';
      result.style.color = '#cf222e';
      report('honeypot', 'critical', 'click-guard', '敏感按钮在风险环境中被点击', {
        framed: inFrame,
        hidden: docHidden,
        ancestorOrigins: state.ancestorOrigins
      });
      log('敏感点击被拦截（嵌套=' + inFrame + '，隐藏=' + docHidden + '）', 'critical');
      return;
    }
    result.textContent = '演示环境：点击已记录，未发生真实交易。';
    report('business', 'info', 'click-guard', '敏感按钮正常点击', { framed: false });
    log('敏感按钮在顶层窗口被正常点击。');
  });

  // 全局异常兜底：任何脚本错误都给出提示并上报，避免白屏无反馈
  window.addEventListener('error', function (ev) {
    log('脚本异常：' + ev.message, 'warning');
    report('error', 'warning', 'window-onerror', '页面脚本发生异常', {
      message: ev.message, filename: ev.filename, lineno: ev.lineno
    });
  });
  window.addEventListener('unhandledrejection', function (ev) {
    report('error', 'warning', 'promise', '未处理的 Promise 异常', { reason: String(ev.reason) });
  });

  /* --------------------------------- 启动 --------------------------------- */
  try {
    if (cfg.jsFrameBust === false) {
      renderPill('framebust', false, 'JS 防嵌套运行中', 'JS 防嵌套已关闭（控制台配置）');
      detectFraming();
      document.body.classList.toggle('is-framed', state.framed);
    } else {
      renderPill('framebust', true, 'JS 防嵌套运行中', 'JS 防嵌套已关闭');
      frameBust();
    }

    if (cfg.workerMonitor === false) {
      renderPill('worker', false, 'Worker 监测运行中', 'Worker 监测已关闭（控制台配置）');
    } else {
      startWorkerMonitor();
    }

    // 嵌套环境中的持续复检（攻击者可能延迟操作）
    setInterval(function () {
      if (cfg.jsFrameBust !== false && !state.blocked) {
        const info = detectFraming();
        if (info.framed && !state.framed) frameBust();
      }
    }, 3000);
  } catch (err) {
    // 启动阶段任何意外都要可见
    try { showBanner('防护脚本初始化异常', String(err && err.message || err), false); } catch (e2) {}
    report('error', 'critical', 'bootstrap', '防护初始化异常', { error: String(err) });
  }
})();
