# dsh-remote-link 远程接入排查记录

> 本文件记录远程扫码接入（二维码 + 公网隧道）过程中发现的所有问题、根因、
> 修复状态，以及当前运行状态与重启操作手册。撰写时间：2026-08-15（会话中途，
> 用户暂停修复，自行重新排查）。

---

## 0. 当前状态快照（撰写时点）

| 组件 | 状态 | 说明 |
|---|---|---|
| DSH web（真实上游） | ✅ 运行 | `127.0.0.1:49152`（DSH Desktop GUI，本会话所在进程） |
| 插件网关 | ❌ **未运行** | `runner-gateway.mjs` 已被 kill，`127.0.0.1:3081` 未监听 |
| localtunnel 客户端 | ✅ 运行 | PID 31486，`node .../localtunnel/bin/lt.js --port 3081` |
| 隧道域名 | ✅ 已分配 | `https://slow-clocks-mix.loca.lt`（重启后可能变化） |
| 隧道连通性 | ❌ 不可达 | 网关未起 → localtunnel 转发到 3081 失败（`000`） |
| scan-me.png | ✅ 存在 | 见 §4 |

**结论：现在整条链路是断的（网关没起）。** 要恢复，按 §5 操作手册执行。

---

## 1. 二维码问题全记录

### 1.1 手写编码器的 4 个 bug（已被替换，保留记录）

旧 `src/qrcode.js` 是手写 QR 编码器（v1–10、ECC L），存在 4 个独立缺陷，
导致产物"结构自洽但扫码器无法识别"（Vision / zbar 全部拒绝）：

| # | 位置 | 问题 | 影响 |
|---|---|---|---|
| 1 | `drawFunctionPatterns` finder | 环逻辑 `ring !== 1`，应为 `ring !== 2`（外圈/内圈/中心三块画反） | 定位图形比例错误，扫码器找不到码 |
| 2 | `scripts/vision-decode.mjs` | 1-bit 灰度 PNG 中 1=白、0=黑，深色模块却写 bit 1 | 整个 PNG 是反色负片 |
| 3 | `drawFormatBits` copy 1 | 格式信息写在了**转置**位置（应写列 8，写到了行 8） | 扫码器按规范位置读取 → 错误 mask → 数据解不出 |
| 4 | `rsComputeEcc` | Reed–Solomon 除法生成多项式系数按**反序**使用 | ECC 码字算错 |

**修复**：bug 1/3/4 已修复并通过测试；随后按用户要求**整体替换**为 vendored 的
qrcode-terminal 编码核心（Kazuhiko Arase QRCode，MIT，见 §1.4）。bug 2 已修复。

### 1.2 配对页短码路径 bug（已修复）

`src/pairing-page.js` 的 verify 请求体**永远只带 `sid`**；短码路径的 proof 用
短码作密钥，但服务端按 sid 找到配对后用随机 secret 校验 → 必然 `BAD_PROOF`。
修复：短码路径发送 `{ code: ... }`（服务端按 code 取密钥），QR 路径仍发 `{ sid }`。

### 1.3 二维码 URL 路径 bug（已修复，真机测试发现）

二维码 URL 原为 `<base>/#p=sid.secret`——**根路径未认证时返回 401**，而读取
fragment 的配对页在 `/pair`。手机扫码 → 401，配对流程根本不会发生。
修复：二维码 URL 改为 `<base>/pair#p=sid.secret`（`src/index.js` 启动日志 +
`src/tools.js` remote_qr 工具同步修改）。

### 1.4 编码/渲染方案（当前）

- **编码**：vendored `src/vendor/QRCode/`（qrcode-terminal 核心，Kazuhiko Arase，
  MIT），ECC 恒为 L，版本 1–40 自动。`src/qrcode.js` 提供
  `encodeQr(text, {border})`（返回矩阵，vision-decode.mjs 用它画 PNG）、
  `pickVersion`、`rsComputeEcc`（薄封装）。
- **UTF-8 补丁**：原版 `QR8bitByte.js` 把 UTF-16 码元直接截 8 位，中文/emoji
  必坏；已打标准 UTF-8 补丁（含 4 字节代理对），Vision 真扫验证
  `任意文本` / `Hi 👋 世界` 均 `ROUND-TRIP OK`。
- **终端渲染**：vendored `src/vendor/qrcode-terminal.js`（lib/main.js，MiMo 同款），
  `renderQr(url, { small: true })` 默认小尺寸半块字符；`small:false` 为 ANSI
  彩色块（**仅适合真终端，纯文本/聊天中不可见——全是空格**）。

### 1.5 ASCII 二维码在聊天里"断裂/乱码"（根因 + 修复）

**现象**：聊天里显示的 ASCII 码白区过宽、黑块不连续，像乱码。

**根因**：markdown 代码块中断。旧 `renderAscii` 输出首行是 45 个空格（能开启
代码块），但数据行只有 **2 个前导空格**（半块渲染下 2 模块边框 = 2 字符）
→ 代码块在第 2 行中断 → 剩余行按**比例字体**渲染 → 空格窄、块字符宽 → 错位。
（art 本身结构正确：23 行、统一 45 字符宽，zbar 原样解码成功。）

**修复**：① 工具（`remote_qr`）输出用 **``` 代码围栏** 包裹，保证 monospace；
② 渲染器切换到 qrcode-terminal `renderQr`（有可见的 ▄/█ 边框，且不再依赖
前导空格开代码块）。`renderQr` 输出已用 zbar 真扫验证解出 URL 完全匹配。

### 1.6 验证方法（真扫，非结构断言）

```sh
# Vision 回环（需 swift）
node scripts/vision-decode.mjs "任意文本"
node scripts/vision-decode.mjs "https://.../pair#p=..."        # 长 URL
# zbar 独立解码（已 brew install zbar）
/opt/homebrew/Cellar/zbar/0.23.93_4/bin/zbarimg scan-me.png
# 测试套件
node --test test/*.test.js          # 当前 87 项全过
```

---

## 2. 隧道问题全记录

### 2.1 为什么需要隧道

本机 `192.168.1.100`（NAT 后），公网只有 IPv6（`2408:xxxx:...`，运营商
CGNAT 可能性大）。手机用**流量**无法直达局域网 IP，必须经公网中转。
**手机 Wi-Fi 或流量均可**——只要手机能上公网；瓶颈在"Mac→隧道服务器"或
"手机网络→隧道服务器"，与手机接入方式无关。

### 2.2 cloudflared quick tunnel（失败，已弃用）

- 尝试：`cloudflared tunnel --url http://127.0.0.1:3081`
- 失败过程：
  1. 默认（QUIC）：预检报 **UDP/7844 被阻断**，隧道未建立；
  2. `--protocol http2 --edge-ip-version 4`：连接注册成功（lax08），
     但**边缘 POP（如 SJC）对请求返回 404**，始终不通。
- 结论：当前网络出口对 cloudflared 不友好。若改用 **Cloudflare Named Tunnel**
  （需你自己的 Cloudflare 账号 + 域名，`cloudflared tunnel login` 创建），
  才有 Zero Trust 后台可查——**当前 URL 与 Cloudflare 无关**。

### 2.3 localtunnel（当前方案）

- 命令：`npx -y localtunnel --port 3081` → 输出 `https://<随机>.loca.lt`
- 数据面：Mac 出站连 `localtunnel.app:19333`（长连接），手机 → loca.lt 服务器
  → 该长连接 → 本机 3081。
- **已知问题**：
  1. **客户端会意外退出**（exit 0、日志无错误）→ 隧道断 → 手机 Bad gateway；
  2. **重启后域名变化**（`dark-houses-shine` → `slow-clocks-mix`），旧域名失效；
  3. 手机端曾出现 Bad gateway：loca.lt → Mac 转发失败（本机链路抖动），或
     **国内网络到 loca.lt 本身不稳定**（免费服务，间歇性被限）；
  4. 网关重启瞬间隧道短暂返回 400（重连抖动，可自愈）。
- **更稳的启动方式**（绕开 npx 包装进程）：
  ```sh
  node ~/.npm/_npx/75ac80b86e83d4a2/node_modules/localtunnel/bin/lt.js --port 3081
  ```

### 2.4 排障判断口诀

| 现象 | 含义 | 查哪里 |
|---|---|---|
| 手机 Bad gateway / 502 | 手机到达了 loca.lt，但转发不回 Mac | localtunnel 进程、网关进程、长连接 |
| 手机 000 / 无法连接 | 手机网络到 loca.lt 不通 | 换 Wi-Fi/运营商对比 |
| 本机 curl 隧道 200、手机不通 | 坐实 loca.lt 在你手机网络上被限 | 换隧道方案（Named Tunnel 等） |
| 本机 curl 隧道也失败 | Mac→loca.lt 链路断 | localtunnel 进程、出站连接 |

---

## 3. 测试用的临时文件

| 文件 | 用途 |
|---|---|
| `scan-me.png` | 手机扫码用的大图（8-bit 灰度，zbar 验证可扫） |
| `scan-me.pgm` | 同上（P5 格式源） |
| `runner-gateway.mjs` | 独立网关运行器（mock ctx，代理真实 DSH web 49152；argv: publicUrl 端口 目标端口） |
| `/tmp/smoke*.mjs` `/tmp/phonesim.mjs` `/tmp/qrtverify.mjs` 等 | 会话内调试脚本，可删 |

---

## 4. scan-me.png 保存路径

```
~/dsh-remote-link/scan-me.png
~/dsh-remote-link/scan-me.pgm
```
（仓库根目录；生成脚本见会话内 `/tmp/mkqr8*.mjs`，用 `encodeQr(url, {border:4})`
+ 12px/模块渲染，PNG 内容与 URL 用 zbar 验证一致。⚠️ 每次新配对都要重新生成。）

---

## 5. 重新排查 / 恢复操作手册

### 5.1 一键恢复链路（顺序重要）

```sh
# 1) 起网关（指向真实 DSH web 49152；隧道域名以实际为准）
cd ~/dsh-remote-link
node runner-gateway.mjs "https://<当前.loca.lt>" 3081 49152 &

# 2) 若 localtunnel 不在：先起它，等它打印新域名，再执行第 1 步
node ~/.npm/_npx/75ac80b86e83d4a2/node_modules/localtunnel/bin/lt.js --port 3081 &

# 3) 验证
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3081/pair        # 期望 200
curl -s -o /dev/null -w "%{http_code}\n" https://<域名>/pair              # 期望 200
```

### 5.2 铸新配对

重启 `runner-gateway.mjs` 即铸新配对（启动日志含二维码 + 短码），或用
`remote_qr` 工具。**新配对必须同时更新 `scan-me.png`**（§4）。

### 5.3 完整手机流程自测（模拟扫码）

```sh
BASE=https://<域名>
# 配对页（应 200 且是配对页）
curl -s "$BASE/pair" | grep -c "DSH Remote Link 配对"
# challenge → HMAC proof → verify → cookie → 官方 UI（见会话内 /tmp/phonesim.mjs 完整脚本）
```

---

## 6. 未提交的改动清单（git status 摘要）

```
 M README.md            # publicUrl 配置表、QR 路径、编码器来源、测试数 87
 M docs/PAIRING-DESIGN.md
 M scripts/vision-decode.mjs    # PNG 极性修复 + /pair 路径
 M src/config.js        # 新增 publicUrl 配置
 M src/index.js         # publicUrl、/pair 路径、renderQr
 M src/pairing-page.js  # 短码路径 verify body
 M src/qrcode.js        # 重写为 vendored 封装 + renderQr
 M src/tools.js         # /pair 路径、renderQr + 代码围栏
 M test/*.js            # 对应测试更新 + python-qrcode RS 真值向量
?? runner-gateway.mjs   # 临时运行器（不入库建议）
?? scan-me.png / .pgm   # 临时文件（可删）
?? src/vendor/          # vendored qrcode-terminal（编码核心 + 渲染器 + NOTICE.md）
```

---

## 7. 下一步建议（待你排查后决定）

1. 先在本机把链路跑通（§5.1），确认"本机 curl 隧道 200"；
2. 手机**两种网络**（Wi-Fi / 流量）各试一次，区分问题在网络侧还是隧道侧；
3. 若 loca.lt 在流量下不可达 → 换 **Cloudflare Named Tunnel**（需账号+域名，
   有后台可查）或自建反代服务器；
4. `runner-gateway.mjs`、`scan-me.*` 建议不入库（测试专用），入库前整理。
