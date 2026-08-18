# Link Keepalive 设计记录（连接保活 + 状态页）

> 2026-08-18。本文记录"断线恢复"专题的完整调研结论与设计决策。
> 结论先行：**不做事件回放，做连接保活**——在网关侧向浏览器方向注入
> WebSocket ping，让空闲连接不被隧道/运营商中间层收割，从根源上避免
> 触发客户端的全量 resync。

---

## 一、调研结论（DSH web 的真实传输与恢复模型）

调研对象：`@deepseek-ai/dsh-client-connection@0.1.0-rc.6`（`lib/client.js`
10k 行 + `lib/index.js` 服务端）、`dsh-client-runtime`、`dsh-host-apiproxy`。

### 1. 浏览器端的传输结构

- 上行：HTTP POST `/api/<method>`（`callUnary`，带客户端超时）。
- 下行：**两条 WebSocket** —— `/api/events.mux`（会话事件/审批/提问）与
  `/api/events.host`（运行位等宿主状态）。SSE 变体（同路径 GET）仅用于
  Node 端，浏览器不用。
- WS 是**纯下行**：客户端发消息会被服务端以 1008 `downlink only` 关闭。

### 2. 服务端没有任何心跳

`WebSocketDownlinks.pump()` 只做 `for await (frame) send(frame)`——
`api.events.mux/host` 流里没有定时帧，`ws` 库也没配 ping。整个事件管线
（grep `setInterval|ping|heartbeat`）无周期性流量。

**后果**：agent 思考/用户挂机期间，网关↔浏览器的 WS 上零字节。这条
连接穿过 cloudflared 边缘与运营商网络，空闲连接会被中间层收割
（Cloudflare 边缘对空闲流的回收通常在 ~90s 量级，且无官方文档保证）。

### 3. 客户端的恢复模型：每代全量重拉

`ConnectionController.loop()`（generation/attempt 私有状态）：

1. 双流打开 + `host.describe` 握手 → `connected`；
2. 任一流断开 → `reconnecting` → 指数退避 → **新 generation**；
3. 重连成功回调 `handleConnected()`：`refreshList()` + **每个打开的会话
   各自 `resync()`**；
4. `resync()` = 把本地 `events/views/pending/liveBuffer` **全部清空**，
   重新 `open()`（全量历史拉取 + 重新订阅）。

会话事件自带连续 `seq`（服务端保证 contiguous），丢失帧是**设计内情况**
——源码注释原话："a frame lost in transit — history still serves it, the
client must repull"。重连订阅 payload 是空对象 `{}`，协议层面**没有
resume 游标**。

### 4. 由此得出的三个设计判断

| 判断 | 依据 |
|---|---|
| **网关侧事件回放没有价值** | 客户端重连后无条件擦空本地状态全量重拉；回放的帧要么被 `pending` 缓冲丢弃、要么与重拉结果重复。ZCode Workspace Bridge 的"补差量"模型在 DSH 客户端上无处落地。 |
| **值得借鉴的是另一半：让连接别断** | ZCode 的 seq/generation 是"断了怎么救"；对 remote-link 更优的杠杆是"让它根本不断"——断连从未发生，resync 成本（全列表刷新 + 每会话全量历史）就从不发生。 |
| **只需保活"网关↔浏览器"方向** | 网关↔上游是回环 TCP（无 NAT/无边缘）；唯一被中间层夹着的是浏览器腿。ping 注入只打浏览器方向，上游 `ws` 服务端零感知。 |

## 二、方案：边界感知的 WS ping 注入

### 机制

对每条代理的 WS 连接（`proxyUpgrade` 建立 101 之后）：

1. **增量帧边界解析器**观察两个方向的字节流（只观察不消费，与 `pipe`
   的 data 监听并存）：
   - 上游方向（`upstreamSocket`，服务端帧、不掩码）：用于知道"网关→
     浏览器"流何时处于**帧边界**——只有边界处才允许插入 ping，插进
     半帧会破坏字节流。
   - 下游方向（`downSocket`，客户端帧、掩码）：用于识别浏览器回的
     pong（opcode 0x0A），计算 RTT。
2. **空闲判定 + 注入**：每 `intervalMs`（默认 25s，可配 0 关闭）检查
   上游方向是否空闲（无数据帧超过一个周期）且处于帧边界 → 向
   `downSocket` 写入一个不掩码 ping（`0x89 0x04 <4 字节计数器>`，
   RFC 6455：服务端帧不得掩码）。浏览器内核自动回 pong（对 JS 不可见，
   但产生双向字节流，恰好喂饱沿途所有空闲收割器）。
3. **安全兜底**：解析器遇到 RSV 非零/长度超限（>512MB 视为失步）即置
   `desynced`，该腿**永久停止注入**、只保留纯管道转发（最坏退化成现状，
   绝不破坏数据）。
4. **遥测**：每条腿维护 `{pingsSent, pongRtMs, lastPongAt, framesDown}`
   等，供状态页展示。

### 为什么 ping 而不是应用层心跳帧

- ping/pong 是 WS 控制帧：`ws` 服务端与浏览器**内核**都自动应答，
  双方应用代码零改动、零感知；
- 控制帧允许出现在分片消息之间（RFC 6455 §5.4），在帧边界注入完全合法；
- 不消耗 DSH 协议的帧 schema（mux/host 帧解析器会严格 parse，注入
  未知应用帧会被当 malformed 丢帧甚至触发 gap 检测）。

### 状态页 `/status`（与 `/qr` 同款回环守卫）

桌面浏览器打开 `http://127.0.0.1:<port>/status`：网关 uptime、升级代数
（generation，即累计 WS 腿数）、每条腿的 {存活时长, ping RTT, 注入次数}、
配对倒计时。`/status.json` 供脚本取数。仅回环且无代理链可见（与
`/qr.png` 相同策略，避免成为公网侦察面）。

## 三、明确不做的事（决策记录）

1. **不做事件回放/seq 补发**——客户端模型不接收（见上）。
2. **不做上游连接保持**（下游断了继续养上游 WS）——客户端重连必开新
   WS、新订阅；养着的旧流没有接收方，纯浪费。
3. **不动上游腿**——回环 TCP 无收割风险，少一层注入少一分风险。
4. **不做 SSE 路径保活**——浏览器不用 SSE；Node 端变体与本插件无关。

## 四、配置

```yaml
# cordis.yml 插件行
- id: remote-link
  name: './dsh-remote-link'
  config:
    keepaliveIntervalMs: 25000   # 0 = 关闭；范围 0..300000
```

## 五、验证口径

- 解析器单测：掩码/非掩码、7/16/64 位长度、分片消息、控制帧交错、
  任意切块喂入、失步兜底。
- 集成测：真实 TCP + 手搓 WS 握手（`node:http` upgrade + SHA1 Accept），
  断言 ①空闲后收到 ping ②pong 回路产出 RTT ③大帧慢发期间 ping 不插入
  帧内（数据零损坏）④关闭后资源释放。
- 全量 `node --test test/` 回归。

---

## 六、v1.6.1 增补（2026-08-18）

v1.6 落地后的复盘补齐三件事：

1. **死腿清理**：`outstanding.size >= 3`（≈3×interval 的单向静默）从"停止注入"
   升级为**主动断开**。半开的移动连接 TCP 侧可能挂几分钟才有 FIN，客户端
   的重连循环被白白拖住；网关代为收尸，客户端立刻进入下一代重连。
2. **连接身份**：腿从匿名的 `{id, path}` 升级为
   `{id, path, ip, auth, deviceId, deviceName}`——认证 verdict 里已有
   `deviceId`（cookie 路径），配 `listDevices()` 映射人类可读名。
   `/status` 终于能回答"这条连接是谁的"。
3. **全链路健康**：状态页新增上游健康（`target` + `lastOkAt` + 最近 10 条
   代理错误环）与隧道连接器心跳（`cf-tunnel.sh` 存活期间每 30s 写 epoch 秒
   到 `$TUNNEL_HEARTBEAT`，网关读文件算年龄；秒→毫秒换算在网关侧完成）。

顺手修掉的 API 毛边：`pairing` 启用而 `pairLimiter` 未传时网关会直接崩
（`null.check`）——现在回落到主限速器，配对端点永不限速敞开。

新增测试锁定：RSV 位置容忍（未来 permessage-deflate 帧的边界仍可解析）、
dispose 后监听器/定时器彻底摘除、死腿清理、cookie 腿身份、上游错误环、
心跳年龄。全量 102/102。

---

## 七、宿主遥测（v1.6.3，2026-08-18）

借鉴自一款协议级遥控插件的架构分享（其核心洞察："Harness ApiProxy 是最好的
注入点"）。remote-link 与它坐在同一 seam 的不同层次：它进程内消费 ApiProxy
的类型化接口，我们转发其 HTTP 表面。本次吸收的是同一 seam 的进程外用法：

1. **RPC 级健康（②）**：网关以官方客户端同款 client-request 信封 POST
   `/api/host.describe`——该调用必须穿过 webserver → ApiProxy → 宿主才能
   返回，成功即全栈存活；往返时间即 RPC 延迟；返回值携带
   model/version/attachedSessions（cwd 出于隐私不展示）。
2. **宿主事件流（①）**：订阅 `/api/events.host` 的 SSE 变体（浏览器用 WS，
   Node 侧 GET 即可），按 `host/session-added/-status/-removed` 增量维护
   会话忙闲表。

**非 DSH 判定按"形状"而非状态码**：MiMo 的兜底 UI 路由（`.all("/*")`）对
一切路径返回 200 HTML——包括 `/api/*`。探针据此把"200 但响应不是
server-response 信封"与 404/501 同等计入"形状不符"，3 次后标记
`supported=false` 并静默（含停掉 SSE）；连接拒绝/超时不计入（那可能是
暂时下线的 DSH，值得继续探测）。真实 MiMo 链路验证：探针曾如实抓到
"MiMo 服务已挂"（ECONNREFUSED）——遥测的第一个实战成果。

**明确不借鉴的部分**（评估记录）：WebRTC/P2P 三层传输与 Service Worker
方案根本拦不了 WebSocket，与"官方 UI 零改动"冲突；Noise E2E 加密需要
拥有两端代码，留给 v2 relay；自有 Android 客户端是另一个产品。
