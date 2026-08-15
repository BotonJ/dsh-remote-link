# dsh-remote-link

把 DeepSeek Harness（DSH）的官方 Web UI **安全地**暴露到局域网——手机打开浏览器即可遥控电脑上的 agent——并给模型增加一个 `fork_session` 会话分叉工具。零核心改动、零运行时依赖。

```
手机/平板 ──Basic Auth──▶ 认证网关(0.0.0.0:3081) ──反代──▶ DSH webserver(127.0.0.1:随机)
                              │  官方前端静态 / /api RPC / /api/events.* WS
                              └─ mDNS 广播 "DSH Remote Link on <Mac>"
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
| `host` | `0.0.0.0` | 网关绑定地址；非 loopback 时**必须**设置 `password`，否则拒绝加载 |
| `port` | `3081` | 网关端口；`0` 为系统随机分配 |
| `username` / `password` | `dsh` / 无 | Basic Auth 凭据 |
| `targetHost` / `targetPort` | `127.0.0.1` / 自动 | 反代目标；默认取宿主 webserver 实际端口 |
| `mdns` | `true` | 非 loopback 绑定时在局域网广播 `_http._tcp` 服务（含 TXT `auth=basic`） |
| `rateLimit` | 60s 300 次 | 每客户端 IP 固定窗口限速 |
| `authFailure` | 5min 10 次失败→封禁 5min | 暴力破解阻尼 |

启动后访问 `http://<局域网IP>:3081`（浏览器弹 Basic Auth），或在手机上直接输入 `http://dsh:<password>@<局域网IP>:3081`。

## fork_session 工具

模型可调用：以**最近一个已完成回合**为边界创建子会话（继承全部上下文，当前会话不受影响），并自动挂回同一工作区。复刻官方 UI "分叉" 按钮的完整配方（边界计算 → `agents.create` 带 seed/meta → `workspace.attachSession`）。对用户说"分个叉试试别的方向"即可触发。

## 安全边界

- 非 loopback 绑定无密码 → **拒绝加载**（与 MiMo server 同款底线）。
- 凭据比较经 SHA-256 摘要后 `timingSafeEqual`（常时比较，不泄露长度）。
- Host 头重写为 loopback 以通过 DSH 信任围栏——这意味着 `settings.*`、`credentials.*` 等特权 RPC **在通过 Basic Auth 后远程可达**：网关的认证就是唯一信任边界，请使用强密码。
- `?token=` 会出现在服务端访问日志/浏览器历史中，属已知折衷（v1.5 的 QR+HMAC 配对将消除）。
- 认证失败独立计数，超限封禁（429 + Retry-After）。

## 开发

```sh
node --test test/*.test.js          # 53 项测试（单元 + 真实 socket 集成）
dsh web --patch overlay.yml --port 0  # 真实冒烟（见 test 断言的场景）
```

零依赖（`node:test` + Node 内置模块）。mDNS 响应器为手写 DNS 编解码（`src/dns-codec.js`），已通过 macOS `dns-sd` 浏览与组播 SRV/TXT/A 解析实测。

**sentinel 发布自扫**：tarball 判定 `review`（6 分）——`gateway.js`/`proxy.js`/`mdns.js` 三个 `JS-IMPORT-NET` medium 即插件本职（认证网关），无 critical/high、无运行时依赖、无生命周期脚本。网络能力全部为**入站监听 + 指向 loopback webserver 的反代**，无任何外联地址。

## 路线图（v1.5+）

- QR + HMAC 配对（替代 URL 明文 token）
- 官方前端 client module 注入（`dsh.client` 声明 + `window.__ModuleLoader__.load()`）
- 中继/外网穿透（AEAD）
