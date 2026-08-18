# MiMo Code 移动端 UI 补丁（2 文件）

让 [dsh-remote-link](../README.md) 的网关也能遥控 **MiMo Code**——手机扫码后打开
MiMo 的移动端 Web UI（会话列表 / 消息流 / 输入框 / SSE 流式输出）。

## 为什么需要这两个文件

MiMo Code 的预编译二进制在构建时硬编码禁用了嵌入式 Web UI
（`script/build.ts` 中 `const skipEmbedWebUi = true`），`GET /` 返回 503
"Web UI is temporarily unavailable"。这里提供修改后的两个文件，恢复一个
轻量的单文件移动端 UI：

| 文件 | 作用 |
|---|---|
| `ui.ts` | UI 路由：嵌入式 UI 不可用时，读取同目录的 `ui.html` 并附带回退 CSP（而非 503） |
| `ui.html` | 单文件移动端 Web UI（约 900 行，零依赖，含 SSE 逐 token 渲染） |

MiMo 的 HTTP API（会话 CRUD / `prompt_async` / `/event` SSE）是原生的，
**无需修改**。网关侧的认证/配对/隧道由 dsh-remote-link 自己承担，MiMo
上游保持回环 + 无密码即可。

## 安装（MiMo Code 源码版，实测 0.1.6）

```sh
# 1) 下载 MiMo Code 源码并进入目录（bun 直跑 TypeScript，无需编译）
cd MiMo-Code-0.1.6

# 2) 把这两个文件复制到路由目录（覆盖同名文件）
cp <本目录>/ui.ts <本目录>/ui.html packages/opencode/src/server/routes/

# 3) 启动 MiMo server（回环绑定，无密码——认证由网关负责）
bun run packages/opencode/src/index.ts serve --hostname 127.0.0.1 --port 3000

# 4) 启动 dsh-remote-link 网关，指向 3000
node runner-gateway.mjs '' 3081 3000 >| /tmp/rl-gw.log 2>&1 &
```

桌面浏览器打开 `http://127.0.0.1:3081/qr` 出配对二维码，手机（同一
Wi-Fi）扫码即进入 MiMo 移动端 UI。**外网（流量）访问**：启动
`scripts/cf-tunnel.sh`，并把第 4 步的第一个参数换成你的公网地址
（如 `https://your.domain`），二维码即指向公网。

## 注意事项

- **必须用源码版**：预编译二进制的 Web UI 路由在构建期就被禁用，放文件也没用。
- **保活说明**：MiMo 的事件流是 SSE 且自带 10 秒心跳，天生不怕空闲收割；
  网关的 WS keepalive 对它基本不生效（这是 DSH "零心跳 + WebSocket" 才有的问题）。
- `ui.html` 兼容 MiMo 自身的 `?token=` 认证旁路（URL 无 token 时自动省略，
  配合无密码回环上游正合适）。

## 出处与许可

- `ui.ts`：衍生自 MiMo Code（MIT License，Copyright (c) 2026 MiMo Code,
  Xiaomi Corporation；Copyright (c) 2025 opencode），修改内容为上述回退
  分支。原许可证见 MiMo Code 仓库 `LICENSE`。
- `ui.html`：原创实现，MIT License，随本仓库发布。
