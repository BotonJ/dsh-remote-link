/**
 * The v1.5 management surface, in the v1 spirit of "tools are the panel":
 *
 *   remote_qr      — mint a one-time pairing (QR URL + ASCII art + short code)
 *   remote_devices — list / revoke / revoke-all paired devices
 *
 * No UI work: the model renders results in the official chat, so "给我配对码"
 * and "踢掉我的旧 iPad" are the whole admin experience.
 */

import { encodeQr, renderAscii } from './qrcode.js'

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

export function defineRemoteQrTool({ createPairing, baseUrl, now = () => Date.now() }) {
  return {
    name: 'remote_qr',
    description:
      '生成一次性远程配对二维码：手机扫码即可通过 HttpOnly 会话接入官方 Web UI（无需输密码）。' +
      '每次调用都会作废上一次未使用的配对？不会——每次都是独立的新配对，5 分钟内有效且只能用一次。' +
      '用户说"我要连手机 / 给我配对码"时调用。无需参数。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => {
        if (value === null || value === undefined) return [{ type: 'text', text: '(no result)' }]
        if (value.ok !== true) return [{ type: 'text', text: `生成配对失败：${value.error ?? 'UNKNOWN'}` }]
        const qr = renderAscii(encodeQr(value.url, { border: 2 }))
        return [{
          type: 'text',
          text: `手机扫码配对（${value.secondsLeft}s 内有效）：\n${qr}\n${value.url}\n无法扫码？在任意设备打开网关输入短码：${value.shortCode}`,
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
        url: `${baseUrl()}/#p=${pairing.sid}.${pairing.secret}`,
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
