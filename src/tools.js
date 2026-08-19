/**
 * The v1.5 management surface, in the v1 spirit of "tools are the panel":
 *
 *   remote_qr       — mint a one-time pairing (QR URL + ASCII art + short code)
 *   remote_devices  — list / revoke / revoke-all paired devices
 *   remote_recovery — generate + activate the long-term recovery code (or check status)
 *
 * No UI work: the model renders results in the official chat, so "给我配对码"
 * and "踢掉我的旧 iPad" are the whole admin experience.
 */

import { randomBytes } from 'node:crypto'

const RESULT_SCHEMA = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    url: { type: 'string' },
    shortCode: { type: 'string' },
    expiresAt: { type: 'number' },
    secondsLeft: { type: 'number' },
    devices: { type: 'array', items: { type: 'object' } },
    revoked: { type: 'number' },
    error: { type: 'string' },
  },
  additionalProperties: false,
}

export function defineRemoteQrTool({ createPairing, baseUrl, qrImageUrl = null, now = () => Date.now() }) {
  return {
    name: 'remote_qr',
    description:
      '生成一次性远程配对二维码：手机扫码即可通过 HttpOnly 会话接入官方 Web UI（无需输密码）。' +
      '配对 5 分钟内有效且只能用一次；有效期内重复调用复用当前配对（终端日志、/qr 页与聊天里的码保持一致），' +
      '配对完成或过期后自动铸新码。用户说"我要连手机 / 给我配对码"时调用。无需参数。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => {
        if (value === null || value === undefined) return [{ type: 'text', text: '(no result)' }]
        if (value.ok !== true) return [{ type: 'text', text: `生成配对失败：${value.error ?? 'UNKNOWN'}` }]
        // The official Web UI renders absolute http(s) markdown images directly,
        // and a raster PNG is immune to chat-font breakage that garbles
        // half-block terminal art. ASCII stays in the real terminal log only.
        const image = qrImageUrl === null ? '' : `\n\n![DSH 配对二维码](${qrImageUrl()})\n`
        return [{
          type: 'text',
          text: `手机扫码配对（${value.secondsLeft}s 内有效）：${image}\n${value.url}\n无法扫码？在任意设备打开网关输入短码：${value.shortCode}`,
        }]
      },
    },
    timeoutMs: 10_000,
    isConcurrencySafe: () => false,
    async execute(_args, exec) {
      void exec
      const pairing = createPairing()
      const t = now()
      return {
        ok: true,
        // /pair reads the #p= fragment and runs the challenge-response
        url: `${baseUrl()}/pair#p=${pairing.sid}.${pairing.secret}`,
        shortCode: pairing.shortCode,
        expiresAt: pairing.expiresAt,
        secondsLeft: Math.max(0, Math.round((pairing.expiresAt - t) / 1000)),
      }
    },
  }
}

export function defineRemoteDevicesTool({ service }) {
  return {
    name: 'remote_devices',
    description:
      '管理已配对的远程设备：list 列出全部（含名称与最后活跃时间）；revoke 按 deviceId 或名称踢掉指定设备；' +
      'revoke-all 全部吊销。被吊销设备的会话立即失效。用户说"看看谁连过我 / 踢掉我的旧 iPad"时调用。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'list | revoke | revoke-all' },
        target: { type: 'string', description: 'revoke 时的设备 ID 或名称' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => {
        if (value === null || value === undefined) return [{ type: 'text', text: '(no result)' }]
        if (value.ok !== true) return [{ type: 'text', text: `操作失败：${value.error ?? 'UNKNOWN'}` }]
        if (value.devices !== undefined) {
          if (value.devices.length === 0) return [{ type: 'text', text: '当前没有已配对设备。' }]
          const rows = value.devices.map((d) => `• ${d.name ?? d.deviceId} — 最后活跃 ${new Date(d.lastSeenAt).toISOString()}`)
          return [{ type: 'text', text: `已配对设备 ${value.devices.length} 台：\n${rows.join('\n')}` }]
        }
        return [{ type: 'text', text: `已吊销 ${value.revoked} 台设备。` }]
      },
    },
    timeoutMs: 10_000,
    isConcurrencySafe: () => false,
    async execute(args) {
      const action = args?.action
      if (action === 'list') {
        const devices = service.listDevices().map((d) => ({
          deviceId: d.deviceId,
          ...(d.name === undefined ? {} : { name: d.name }),
          addedAt: d.addedAt,
          lastSeenAt: d.lastSeen,
        }))
        return { ok: true, devices }
      }
      if (action === 'revoke') {
        const target = args?.target
        if (typeof target !== 'string' || target.length === 0) {
          return { ok: false, error: 'BAD_TARGET', message: 'revoke 需要 target（deviceId 或设备名）' }
        }
        return { ok: true, revoked: service.revokeDevice(target) }
      }
      if (action === 'revoke-all') {
        return { ok: true, revoked: service.revokeAllDevices() }
      }
      return { ok: false, error: 'BAD_ACTION', message: 'action 必须是 list | revoke | revoke-all' }
    },
  }
}

export function defineRemoteRecoveryTool({ service, random = defaultRecoveryRandom, baseUrl = null }) {
  const RECOVERY_SCHEMA = {
    type: 'object',
    properties: {
      ok: { type: 'boolean' },
      code: { type: 'string' },
      source: { type: 'string' },
      createdAt: { type: 'number' },
      pairUrl: { type: 'string' },
      error: { type: 'string' },
    },
    additionalProperties: false,
  }
  return {
    name: 'remote_recovery',
    description:
      '管理长期恢复码（所有配对设备丢失时的自救后门）。setup：生成高熵随机码并立即启用——码只在本次回复里出现一次，' +
      '提醒用户马上保存到密码管理器或打印离线；再次 setup 会轮换旧码。status：查看是否已启用及来源。' +
      '用户说"设置恢复码 / 生成恢复码 / 恢复码是什么状态"时调用。',
    parameters: {
      type: 'object',
      properties: { action: { type: 'string', description: 'setup（默认）| status' } },
      additionalProperties: false,
    },
    output: {
      schema: RECOVERY_SCHEMA,
      render: (_args, value) => {
        if (value === null || value === undefined) return [{ type: 'text', text: '(no result)' }]
        if (value.ok !== true) return [{ type: 'text', text: `操作失败：${value.error ?? 'UNKNOWN'}` }]
        if (value.code !== undefined) {
          return [{
            type: 'text',
            text:
              '✅ 恢复码已生成并启用。**这是唯一一次展示，请立即保存**（密码管理器 + 建议打印离线）：\n\n' +
              `\`${value.code}\`\n\n` +
              `用法：所有设备丢失时，在任意设备打开 ${value.pairUrl ?? '<网关地址>/pair'}，选择"恢复接入"输入此码即可重新进入；` +
              '每次恢复会注册为一个可吊销设备。此码等同主密码——泄露即换（再说一次"重新生成恢复码"）。',
          }]
        }
        const source = value.source === 'tool' ? '工具生成（recovery.json）' : value.source === 'config' ? '配置文件（pairing.recoveryCode）' : null
        return [{
          type: 'text',
          text: source === null
            ? '恢复码未启用。说"设置恢复码"即可生成并启用（或手工配置 pairing.recoveryCode，≥16 字符）。'
            : `恢复码已启用（来源：${source}${value.createdAt === undefined ? '' : `，生成于 ${new Date(value.createdAt).toISOString()}`}）。出于安全不再展示码本身；轮换请说"重新生成恢复码"。`,
        }]
      },
    },
    timeoutMs: 10_000,
    isConcurrencySafe: () => false,
    async execute(args) {
      const action = args?.action ?? 'setup'
      if (action === 'status') {
        const status = service.recoveryStatus()
        return { ok: true, ...(status.enabled ? { source: status.source, ...(status.createdAt === undefined ? {} : { createdAt: status.createdAt }) } : { source: 'none' }) }
      }
      if (action === 'setup') {
        const code = random()
        const result = service.setRecoveryCode(code)
        if (result.ok !== true) return { ok: false, error: result.error }
        return { ok: true, code, createdAt: result.createdAt, ...(baseUrl === null ? {} : { pairUrl: `${baseUrl()}/pair` }) }
      }
      return { ok: false, error: 'BAD_ACTION', message: 'action 必须是 setup | status' }
    },
  }
}

function defaultRecoveryRandom() {
  // 24 random bytes, base64url ≈ 32 chars ≈ 144 bits of entropy.
  return randomBytes(24).toString('base64url')
}
