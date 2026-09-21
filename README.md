# 🛡 防嵌套防护实验室（frame-ancestors / JS 防嵌套 / UI 欺骗检测）

一个零依赖的本地安全教学实验室，演示并验证「点击劫持 / 页面嵌套」的**多层防护、可复现绕过、事件报告与异常处理**。
技术栈：**iframe + CSP（frame-ancestors / report-uri）+ X-Frame-Options + 原生 JS + Web Worker**。

## 快速开始

```bash
node server.js          # 需要 Node.js >= 16，无任何 npm 依赖
# 或 npm test 运行 11 组自动化断言（内存级 mock，无需联网/端口）
```

启动后得到三个来源（用端口模拟不同站点，无需配置 hosts）：

| 角色 | 地址 | 说明 |
| --- | --- | --- |
| 受保护站点 / 控制台 | http://localhost:8080 | 防护开关、实时报告、受保护页 `/protected` |
| 攻击者站点 | http://localhost:9001 | 点击劫持、sandbox 绕过、多层嵌套三个实验 |
| 可信合作方 | http://localhost:9002 | 在 `frame-ancestors` 白名单内的合法嵌套 |

> 端口可通过环境变量 `PORT_DEFENDER / PORT_ATTACKER / PORT_PARTNER` 修改。

## 防护体系（多层、纵深防御）

按强度从外到内排列，任何单层失效时仍有后续防线：

1. **CSP `frame-ancestors`（主防线）** — 服务端按控制台开关动态下发响应头。浏览器在**渲染之前**裁决整个祖先链，JS 都不会执行，攻击者无法从页内绕过。支持 `'self' + 白名单来源`，并带 `report-uri` 上报违规。
2. **`X-Frame-Options`（旧浏览器兜底）** — 白名单模式 `ALLOW-FROM http://localhost:9002`，严格模式 `DENY`。覆盖 IE8+/旧版 Edge 等不支持 CSP2 的环境。
3. **CSP Report-Only 演练模式** — 只上报不拦截，用于灰度观察嵌套来源。
4. **JS 防嵌套（`protected.js`）** — `top !== self` 自检、`ancestorOrigins` 白名单核验（Chromium 系）、非白名单来源时全屏红色遮挡 + `top.location` 逃生跳转。每步 try/catch，被 sandbox 阻止时会**记录一条「frame-busting 被绕过」证据**。
5. **Web Worker UI 欺骗检测（`monitor.worker.js`）** — 独立线程做调度/判定，主线程只负责采集 DOM 事实：
   - 透明覆盖层（`elementFromPoint` 探测敏感按钮中心点是否被遮挡，连续 2 次确认）；
   - 页面隐藏中发生点击、点击前长时间失焦、点击前无鼠标移动（合成/诱导点击）；
   - Worker 计时器漂移、主线程探测应答超时、Worker 心跳连续超时（标签页挂起 / 调试器冻结对抗）；
   - 关键原生 API（`window.open`、`addEventListener`、`elementFromPoint` 等）被 hook 的完整性校验。
6. **敏感操作蜜罐守卫** — 嵌套/隐藏环境下的「确认转账」点击直接拦截并上报，不执行业务。

Worker 不可用时自动降级为主线程子集检测（visibility + 计时器漂移）。

## 绕过演示（全部可复现）

在控制台 http://localhost:8080 切换开关后，**刷新实验页**即可（响应头在每次请求时重新生成）：

| 实验 | 页面 | 操作 | 预期 |
| --- | --- | --- | --- |
| 经典点击劫持 | :9001 `/` | 防护全开 → 点「立即领取 1000 元」 | iframe 区域空白，浏览器拒绝渲染；控制台出现 `csp` 报告（可勾选「显示 iframe 轮廓」看穿结构） |
| 防线逐层拆除 | 同上 | 依次关闭 CSP → 刷新；再关 XFO → 刷新；再关 JS → 刷新 | 直观看到「主防线失效后由谁兜底」，最终全关时蜜罐点击仍被拦截并上报 |
| sandbox 绕 frame-busting | :9001 `/sandbox.html` | 关闭 CSP+XFO，切换 4 种 sandbox 组合 | `allow-scripts`（不给 `allow-top-navigation`）吞掉逃生跳转：红色遮挡横幅出现、报告记录 `顶层跳转被阻止`；加回 `allow-top-navigation` 后跳转恢复 |
| 多层嵌套 | :9001 `/double.html` | 默认配置 | `frame-ancestors` 校验**整条祖先链**而非仅 parent，:9001 出现在链中即被拒 |
| 白名单合法嵌套 | :9002 `/` | 默认 / 关闭「白名单合作方」对比 | 默认可正常加载；关闭后合作方也被拒绝并产生 CSP 报告 |
| 演练模式 | 控制台 | 打开「CSP Report-Only」 | 页面正常渲染但产生 `severity=warning` 的 CSP 报告 |

报告链路在真实浏览器中验证方式：浏览器拦截嵌套时会向 `/api/csp-report` 发送标准 CSP violation report；页面内事件经 `sendBeacon`（卸载可达）→ `fetch keepalive` 兜底发往 `/api/report`。

## 浏览器兼容性

- **frame-ancestors**：Chrome 40+、Firefox 35+、Edge、Safari 10.5+；IE 全系不支持 → 由 XFO 兜底。
- **X-Frame-Options**：全主流浏览器（含 IE8+）；`ALLOW-FROM` 仅旧 IE/旧 Edge 识别，现代浏览器忽略它但同时尊重 frame-ancestors。
- **Web Worker / sendBeacon / Visibility API**：Chrome、Firefox、Safari、Edge 均支持；任一缺失都有降级与提示（控制台页有当前浏览器能力自检表）。
- **`location.ancestorOrigins`**：仅 Chromium 系提供；缺失时 JS 不做来源误判，授权裁决完全交给浏览器层 CSP（避免在 Firefox/Safari 误伤合作方）。

## 报告与导出

- 控制台「安全事件报告」表格每 6 秒自动刷新，支持按**类型 / 级别**过滤；
- **导出 CSV**（含逗号/引号/换行转义，Excel 可直接打开）、**导出 JSON**（带导出时间与计数）；
- 服务端保留最近 2000 条，内存态，重启清空；接口：
  - `GET /api/reports[?kind=&severity=&format=csv|json]`
  - `DELETE /api/reports`
  - `POST /api/report`（页面事件）、`POST /api/csp-report`（CSP 违规，两种格式归一化存储）

## 异常处理（均有明确提示，无白屏/静默失败）

- 报告 JSON 解析失败 → 400 + 中文错误信息；超大请求体（>1MB）直接断开；
- 配置项类型非法 → 400；错误方法 → 405；未知路由/路径穿越 → 404/403；
- Worker 创建失败/运行错误 → 状态灯变红 + 本地日志 + 降级检测；
- 上报失败（离线/拦截）→ 不阻断业务，页面本地事件日志仍保留；
- 防护脚本初始化异常 → 全屏横幅提示；`window.onerror` / `unhandledrejection` 全局兜底上报。

## 目录结构

```
server.js                 零依赖 HTTP 服务：动态 CSP/XFO、配置、报告收集/导出
public/
  index.html              控制台（开关、报告、兼容性自检）
  app.js                  控制台逻辑
  protected.html          受保护页（模拟转账中心）
  protected.js            JS 防嵌套 + Worker 桥接 + 蜜罐守卫 + 异常横幅
  monitor.worker.js       Web Worker：探测调度与 UI 欺骗判定
  attacker/               攻击者站点（:9001）
    index.html            经典透明 iframe 点击劫持
    sandbox.html          sandbox 绕过 frame-busting（4 种组合）
    double.html / inner-shell.html  多层嵌套
  partner/                可信合作方（:9002）
test/smoke.test.js        自动化断言（npm test）
```

## 安全结论

浏览器层的 `frame-ancestors` 是点击劫持唯一无法被宿主页面绕过的防线；JS 防嵌套受 `sandbox`、跨域、禁用脚本等限制，只能用于**遮挡、告警、取证**；Web Worker 让取证在主线程被对抗时仍可存活。三者必须组合使用——这正是各绕过实验要复现的结论。
