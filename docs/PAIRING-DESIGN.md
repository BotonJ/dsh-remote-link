# dsh-remote-link v1.5 设计：QR 配对 + HMAC 挑战-响应

> 状态：设计稿，待评审。前置阅读：`../README.md`（v1 安全边界一节已声明本设计要消除的 `?token=` 折衷）。
> 原则：不动 v1 的代理/限速/mDNS 骨架，只换认证内核 + 加配对面板。零依赖纪律延续。

## 0. 要解决的三个问题（全部来自 v1 的已知折衷）

| v1 痛点 | 根因 | v1.5 解法 |
|---|---|---|
| `?token=<password>` 出现在日志/浏览器历史 | 浏览器 WS/EventSource 无法携带 Authorization 头 | **HttpOnly Cookie 会话**：cookie 随 WS upgrade 自动携带，`?token=` 整条删除 |
| 密码即全部权限，泄漏即永久后门 | 单一共享秘密 | **一次性配对密钥 + 握手后轮换设备密钥**：QR 泄漏 ≠ 可接入 |
| 无设备概念，无法单独吊销 | Basic 只有"知道密码/不知道" | **设备注册表**：一机一档、单独吊销、`lastSeen` 过期 |

## 1. 配对协议（七步）

```
桌面端                                手机浏览器
──────                                ──────────
插件启动/调用 remote_qr 工具
  ├─ 生成 pairing = { sid: 16B random,
  │    secret: 32B random, exp: 5min, uses: 1 }
  └─ 终端 ASCII QR + 聊天内 QR：
     http://<lan-ip>:3081/pair#p=<sid>.<b64url(secret)>
                                        │ 扫码打开（secret 在 fragment，
                                        │ 永不发给服务器）
                                        ▼
                 GET /pair/challenge?sid=…     ← 限速 10/min/IP，nonce 单次有效 60s
                 { nonce: 32B, alg: "HMAC-SHA256", ts }
                                        │
                                        │ proof = HMAC(secret, sid|nonce|ts)
                                        ▼
                 POST /pair/verify {sid, ts, proof}
                        │
        常时比较验证 + 时间窗 ±300s + nonce 作废
        派生 deviceKey = HKDF(secret, "rl-device", sid)  ← 与配对密钥不同源
        注册设备 {deviceId(新随机), name, addedAt, lastSeen}
        pairing 作废（uses=0）
                        │
                        ▼
                 Set-Cookie: rls=<sessionToken(32B)>
                   HttpOnly; SameSite=Strict; Path=/; Max-Age=30d
                 { deviceId }                          ← 之后一切请求（含 WS
                                                          upgrade）cookie 自动携带
```

**关键机制说明**：

- **fragment 藏密钥**：`#p=…` 由页面 JS 读取后只在本地算 HMAC，网络侧永远只见 proof——网关日志/中间设备最多看到 sid。
- **密钥轮换**：设备会话凭据（sessionToken）与配对秘密完全解耦；QR 被拍照、五分钟后被扫，得到的是"pairing 已作废"。
- **重放免疫**：nonce 服务端单次缓存 + ts 时间窗（与 MiMo feishu webhook 同款 ±300s 语义）。
- **纯 JS HMAC**：非 localhost 的 HTTP 页面拿不到 `crypto.subtle`（secure context 限制），配对页内置 ~80 行纯 JS HMAC-SHA256——这是 LAN 模式的硬约束，不是选择。

## 2. v1 代码的落点（贴着现有骨架改）

| v1 模块 | v1.5 改动 |
|---|---|
| `auth.js` | `createAuthenticator` 增加 `via: 'cookie'` 分支：sessionToken → 内存会话表（sha256 存储）+ `via: 'basic'` 保留（curl/桌面浏览器便利）。**`via: 'token'` 删除** |
| `gateway.js` | 路由表加三个端点：`GET /pair/challenge`、`POST /pair/verify`、`GET /pair`（配对页 HTML，~200 行内联字符串，含纯 JS HMAC）；这些路径走**更紧的限速预算**（独立桶 10/min/IP），复用 `ratelimit.js` |
| 新 `pairing.js` | pairing 生命周期（生成/校验/作废）+ 设备注册表 `$DSH_HOME/remote-link/devices.json`（0600）+ 会话表 |
| 新 `qrcode.js` | 单文件 QR 编码器（~300 行，零依赖，Reed-Solomon + 掩码），输出终端 ASCII 与文本两态 |
| `index.js` | 新工具 ×2（见 §3）；启动日志从打印密码改为打印 QR |
| `config.js` | 新段 `pairing: { enabled: true, ttlMs: 300000, sessionMaxAgeDays: 30, deviceIdleExpiryDays: 90 }`；`password` 降级为可选的 Basic 后备（配对启用时可留空） |

## 3. 无 UI 的管理面（延续 v1 哲学：工具即面板）

- **`remote_qr` 工具**：模型可调用，"给我配对二维码"→ 工具结果里渲染 ASCII QR（官方 UI 聊天里直接可见），同时终端打印。`evidence` 含剩余有效期。
- **`remote_devices` 工具**：`list` / `revoke <deviceId|name>` / `revoke-all`。"看看谁连过我 / 踢掉我的旧 iPad" 自然语言即可。
- 兜底：`devices.json` 手删 + 重启，等价 revoke-all。

## 4. 无摄像头场景：短码后备

iPad / 二手设备扫不了自己旁边的屏——`GET /pair` 页支持输入 **6 位短码**（pairing sid 的数字投影，5 分钟有效）：手机连网关任意页 → 输码 → 走同一 challenge-response。同一协议，两个入口。

## 5. 威胁模型（诚实清单）

| 威胁 | v1.5 状态 |
|---|---|
| QR/配对秘密泄漏（拍照、聊天记录） | ✅ 一次性 + 5min TTL + 轮换，泄漏后最多浪费一次配对 |
| proof 重放 | ✅ nonce 单次 + 时间窗 |
| 暴力猜 proof | ✅ 256-bit HMAC + 独立限速桶 + 沿用 v1 封禁窗 |
| **LAN 明文嗅探 → 会话 cookie 被截获** | ❌ 未解决（HTTP 天花板）：嗅探者可复制 cookie 接管会话。缓解：`sessionMaxAgeDays` 调短、设备吊销重置全部会话、v2 走 TLS（tailscale serve / relay 域名）时自动加 `Secure` |
| 网关进程被攻破 | ❌ devices.json 内含 deviceKey 明文（0600 权限），与 v1 密码同级暴露面——文档明示 |
| CSRF | ✅ SameSite=Strict + 一切写操作仍需过网关 |

## 6. 规模与里程碑

| 模块 | 行数估 |
|---|---|
| pairing.js（协议 + 注册表 + 会话） | ~280 |
| qrcode.js（编码器） | ~300 |
| 配对页（内联 HTML/JS，含纯 JS HMAC） | ~200 |
| auth/gateway/index/config 改造 | ~180 |
| 工具 ×2 | ~120 |
| 测试（协议正反路径、重放、限速、QR 译码回环） | ~350 |
| **合计** | **~1,430**（与 v1 同量级） |

验收（DoD）：
1. 手机扫码 → 无弹窗直接进入官方 UI，WS 事件流正常（cookie 通路）；
2. 同一 QR 二次扫码被拒；截获的 proof 重放被拒；
3. `remote_devices revoke` 后该设备下一个请求即 401；
4. 全量回归 v1 的 53 项测试 + sentinel 自扫维持 review 及以下；
5. windtunnel 增补用例：配对正路径 / 坏秘密 / 重放 / 限速，四绿。

## 7. 明确不做（防蔓延）

v2 才做：TLS relay 模式与 `Secure` cookie、AEAD 载荷加密、approval 推送、成本面板、能力分级设备令牌。v1.5 的唯一使命：**把"密码广播"换成"一次配对、按设备吊销"**。
