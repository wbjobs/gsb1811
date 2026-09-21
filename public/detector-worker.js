'use strict';

/**
 * 检测 Worker：独立线程运行，定时向主线程发送心跳。
 * 主线程若被 beforeunload 弹窗 / 长任务冻结，心跳间隔会异常，
 * 由主线程侧判定并上报（见 target.html startWorkerHeartbeat）。
 */
var HEARTBEAT_INTERVAL = 500;

setInterval(function () {
  postMessage({ type: 'heartbeat', ts: Date.now() });
}, HEARTBEAT_INTERVAL);

onmessage = function (e) {
  if (e.data && e.data.type === 'ping') {
    postMessage({ type: 'pong', ts: Date.now() });
  }
};
