# dsh-remote-link

[![Awesome DSH Plugin](https://awesome-dsh-plugin.com/badge.svg)](https://awesome-dsh-plugin.com)

把 DeepSeek Harness（DSH）的官方 Web UI **安全地**暴露到局域网——手机扫码即遥控电脑上的 agent——并给模型增加 `fork_session` 会话分叉工具。零核心改动、零运行时依赖。

**v1.6：链路保活 + 状态页**——DSH 事件下行流（`/api/events.mux`）没有任何心跳，空闲连接会被隧道边缘/运营商 NAT 静默收割，手机端触发全量 resync。网关现按需向浏览器注入 WS ping（仅在帧边界、仅空闲时），从根源避免断连；`/status` 状态页实时展示每条连接的 RTT 与保活计数（调研与设计见 `docs/LINK-KEEPALIVE-DESIGN.md`）。

**v1.6.1：死腿清理 + 连接身份 + 全链路健康**——连续 3 个 ping 无 pong 的半开连接被主动关闭（客户端立刻重连，不再干等 TCP 超时）；`/status` 的每条连接标注设备身份（配对 cookie → 设备名 + 来源 IP）、上游健康（最近成功 + 最近 10 条代理错误）、隧道连接器心跳年龄（`cf-tunnel.sh` 每 30s 落盘，配置 `tunnelHeartbeatFile` 读取）。

**v1.5：QR 一次性配对 + HMAC 挑战-响应 + HttpOnly Cookie 会话 + 设备注册表**（v1 的 `?token=` 明文折衷已删除，设计见 `docs/PAIRING-DESIGN.md`）。

```
手机扫码(→ /pair#p=sid.secret, secret 留在 fragment)
   → GET /pair/challenge?sid  → {nonce, ts}
   → proof = HMAC(secret, sid|nonce|ts)
   → POST /pair/verify        → Set-Cookie rls=<token> (HttpOnly, SameSite=Strict, 30d)
   → 官方 UI / /api RPC / WS 事件流全部走 cookie，无密码无弹窗
```

## 为什么这样设计

- **主 webserver 保持 loopback**：DSH 官方 CLI 明确拒绝 `--host 0.0.0.0`（"would expose remote code execution to the network"）。本插件是"被认可的远程暴露方式"：网关在独立端口做认证，反代到 loopback。
- **官方前端直接复用**：不做自己的 UI（dsh-desktop 也是 Electron 壳 loadURL 官方 UI），聊天框就是遥控器。
- **`?token=` 查询参数认证**：浏览器 WebSocket/EventSource API 无法携带 `Authorization` 头，官方 UI 的事件流（`/api/events.mux`）在手机上必须有这条通路（与 MiMo 移动端方案一致）。

## 安装

```sh
dsh plugin --profile web add ./dsh-remote-link     # 本地目录
# 或 dsh plugin --profile web add github:<you>/dsh-remote-link
```

在 `$DSH_HOME/profiles/web/cordis.patch.yml` 的 `remote-link` 行配置：

| 配置 | 默认 | 说明 |
|---|---|---|
| `host` | `0.0.0.0` | 网关绑定地址 |
| `port` | `3081` | 网关端口；`0` 为系统随机分配 |
| `username` / `password` | `dsh` / 空 | Basic Auth 后备（curl/桌面浏览器便利）；配对启用时可留空 |
| `pairing.enabled` | `true` | QR/短码配对 + cookie 会话；关闭后非 loopback 必须设 `password` |
| `pairing.ttlMs` | `300000` | 配对秘密有效期（5 分钟、一次性） |
| `pairing.sessionMaxAgeDays` | `30` | cookie 会话最长寿命 |
| `pairing.deviceIdleExpiryDays` | `90` | 设备闲置自动出局 |
| `pairing.devicesFile` | `$DSH_HOME/remote-link/devices.json` | 设备注册表（0600） |
| `targetHost` / `targetPort` | `127.0.0.1` / 自动 | 反代目标；默认取宿主 webserver 实际端口 |
| `mdns` | `true` | 非 loopback 绑定时广播 `_http._tcp`（TXT 标注 `auth=pairing|basic`） |
| `publicUrl` | 空 | 二维码/短码的公开基础地址（如 `https://xxx.trycloudflare.com`）；手机走流量/外网时必填，否则二维码指向局域网 IP 不可达 |
| `keepaliveIntervalMs` | `25000` | 空闲 WS ping 注入间隔（仅帧边界注入，浏览器内核自动回 pong）；`0` 关闭。连续 3 个 ping 无 pong 的死腿会被主动断开 |
| `tunnelHeartbeatFile` | 空 | 隧道连接器心跳文件路径（`scripts/cf-tunnel.sh` 每 30s 写入 epoch 秒）；配置后 `/status` 展示连接器存活年龄 |
| `rateLimit` | 60s 300 次 | 每客户端 IP 固定窗口限速 |
| `authFailure` | 5min 10 次失败→封禁 5min | 暴力破解阻尼（配对端点另有独立 10/min 桶） |

启动日志直接打印**一次性配对二维码**（ASCII）+ 6 位短码。手机扫码 → 官方 UI 无弹窗打开；扫不了码就在任意设备打开 `http://<IP>:3081/pair` 输短码。

桌面浏览器打开 `http://127.0.0.1:<port>/status` 可看**链路状态页**：网关运行时长、WS 连接代数、每条连接的设备身份（配对设备名 + 来源 IP）、keepalive ping RTT/收发计数、上游健康（目标 + 最近成功 + 最近错误）、隧道连接器心跳年龄、配对倒计时（`/status.json` 供脚本取数；与 `/qr` 相同的仅回环可见策略）。

## 管理工具（聊天框即面板）

- **`remote_qr`**：铸新的一次性配对（QR URL + ASCII 图 + 短码 + 剩余有效期）——"给我配对码"。
- **`remote_devices`**：`list / revoke <名称或ID> / revoke-all`——"看看谁连过我 / 踢掉我的旧 iPad"；吊销后会话立即失效。

## fork_session 工具

模型可调用：以**最近一个已完成回合**为边界创建子会话（继承全部上下文，当前会话不受影响），并自动挂回同一工作区。复刻官方 UI "分叉" 按钮的完整配方（边界计算 → `agents.create` 带 seed/meta → `workspace.attachSession`）。对用户说"分个叉试试别的方向"即可触发。

## 安全边界

- 非 loopback 绑定且既无密码又关闭配对 → **拒绝加载**。
- 配对秘密 5 分钟一次性；QR 里的 secret 只存在于 URL fragment，**永不发给服务器**；proof 是 HMAC，nonce 单次有效（每次尝试即作废）+ ±300s 时间窗 + 常时比较。
- 会话 cookie：HttpOnly + SameSite=Strict，服务端只存 SHA-256 摘要；吊销设备即刻断线。
- 短码路径以 6 位码为弱共享秘密（20 bit），由独立 10/min 限速桶 + v1 封禁窗 + 5 分钟一次性 TTL 约束，单次配对窗口内猜中概率 ~10⁻⁵。设计稿原定"sid 数字投影"会随 sid 泄漏而可推导，已改为 HMAC 派生（安全修正）。
- **已知未解决（HTTP 天花板）**：LAN 嗅探者可复制 cookie 接管会话；`devices.json` 内含 deviceKey 明文（0600，与进程同权限）。v2 TLS relay 落地后自动收紧。
- Host 头重写为 loopback 以通过 DSH 信任围栏——`settings.*`、`credentials.*` 等特权 RPC 在通过网关认证后可达：网关认证是唯一信任边界。
- 认证失败独立计数，超限封禁（429 + Retry-After）。

## 开发

```sh
node --test test/*.test.js            # 102 项（单元 + 真实 socket 集成 + 配对协议正反路径 + WS 保活/清理/健康）
dsh web --patch overlay.yml --port 0  # 真机冒烟：/pair 页 → challenge → verify → cookie → UI/RPC
node scripts/vision-decode.mjs "..."  # 可选：macOS Vision 真扫一遍自产的 QR（需 swift）
```

零依赖。mDNS 响应器（`src/dns-codec.js`）为手写实现；QR 编码器使用 vendored 的 qrcode-terminal 核心（Kazuhiko Arase QRCode，MIT，`src/vendor/QRCode/`，含 UTF-8 补丁），替代早期手写编码器（曾产出结构自洽但扫码器无法识别的码）。内嵌配对页的纯 JS HMAC-SHA256 与 `node:crypto` 全量交叉验证一致。

**sentinel 发布自扫**：tarball 判定 `review`（6 分）——三个 `JS-IMPORT-NET` medium 即插件本职（认证网关），无 critical/high、无运行时依赖、无生命周期脚本。

**windtunnel**：`remote-link-pairing-happy` 用例绿（3/3 断言 + 17/17 L1 契约）；另三例（坏输入/新配对/headless 挂载）卡在 windtunnel headless 权限流语义（`permission/preset` 后无 `tool/result`），非插件侧问题，留待风洞侧跟进。

## 路线图（v2）

- TLS relay 模式（tailscale serve / relay 域名）+ `Secure` cookie + AEAD
- 官方前端 client module 注入（`dsh.client` 声明 + `window.__ModuleLoader__.load()`）
- approval 推送、成本面板、按设备能力分级
