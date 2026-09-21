# 点击劫持（Clickjacking）攻防演练平台

基于 **iframe + CSP + Web Worker** 的零依赖演示平台，覆盖多种防护策略、绕过手法演示、实时检测与报告导出。

## 启动

```bash
node server.js        # 默认 http://localhost:8080
PORT=9000 node server.js
```

## 功能

- **防护策略**（`/target?defense=…`）
  - `none` 无防护（对照组）
  - `csp-none` / `csp-self`：CSP `frame-ancestors`
  - `xfo`：`X-Frame-Options: DENY`
  - `js-buster`：JS 防嵌套（frame-busting）
  - `combined`：CSP + XFO + JS 组合防护
- **绕过演示**（`/attack?defense=…&technique=…`）
  - `plain` 直接嵌套 · `sandbox` 禁用目标 JS · `opacity` 透明层欺骗
  - `double-frame` 双重嵌套 · `beforeunload` 冻结跳出
- **检测能力**
  - 目标页：嵌套检测、跨域父页探测、UI 欺骗检测（透明度/可见性/视口）、Web Worker 心跳（识别冻结型绕过）
  - 攻击页：加载结果判定（防护是否生效）并上报
  - 服务端：CSP 违规上报端点 `/api/csp-report`
- **报告导出**：仪表盘一键导出 JSON / HTML 报告（`/api/report?fmt=json|html`）
- **异常提示**：页面脚本错误、Worker 异常、接口失败均有 toast / 日志提示

## 目录

```
server.js                  零依赖 Node 服务（防护头下发、事件收集、报告导出）
public/index.html          仪表盘（演练矩阵 + 实时事件 + 报告导出）
public/target.html         被保护目标页（JS 防嵌套 + UI 欺骗检测 + Worker 心跳）
public/attack.html         攻击演示页（5 种绕过手法）
public/detector-worker.js  Web Worker 心跳线程
public/style.css           样式
test.js                    离线测试（mock 请求覆盖全部路由与防护头）
```

## 测试

```bash
node test.js   # 无需启动服务，直接对路由处理器做断言
```

## 验证要点

- 防护生效：`csp-*` / `xfo` / `combined` 下 iframe 被浏览器拦截，攻击页判定“防护生效”
- 绕过可复现：`js-buster` + `sandbox`/`beforeunload` 可绕过纯 JS 防嵌套；`none` 下所有手法均可嵌套
- 兼容性：Chrome / Edge / Firefox / Safari 均支持 `frame-ancestors`；XFO 作为旧浏览器兜底；不支持 Worker 时自动降级并提示
