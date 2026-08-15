/**
 * The fork_session tool: lets the model fork the session it is running in.
 *
 * Mirrors the official web UI's fork RPC (dsh-host-apiproxy `session.fork`):
 * cut at the last completed turn, extend through trailing out-of-band appends
 * (titles, injections) up to the next turn/start, then create the child agent
 * with the prefix as its seed and reattach it to the parent's workspace.
 */

import { randomUUID } from 'node:crypto'

/**
 * @param {readonly { seq: number, type: string }[]} events live session log, contiguous by index
 * @returns {{ boundarySeq: number, cut: number } | null} null when no completed turn exists
 */
export function computeForkBoundary(events) {
  let boundaryIndex = -1
  for (let i = events.length - 1; i >= 0; i -= 1) {
    if (events[i]?.type === 'turn/end') { boundaryIndex = i; break }
  }
  if (boundaryIndex === -1) return null
  let cut = boundaryIndex + 1
  while (cut < events.length && events[cut]?.type !== 'turn/start') cut += 1
  return { boundarySeq: events[boundaryIndex].seq, cut }
}

const FORK_RESULT_SCHEMA = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    childSessionId: { type: 'string' },
    seedLength: { type: 'number' },
    error: { type: 'string', description: 'NO_AGENT | NO_COMPLETED_TURN | CREATE_FAILED' },
    message: { type: 'string' },
  },
  additionalProperties: false,
}

function renderResult(value) {
  if (value === null || value === undefined) return '(no result)'
  if (value.ok) {
    return `已创建子会话 ${value.childSessionId ?? '?'}（继承前 ${String(value.seedLength ?? '?')} 条事件）` +
      (value.message ? `；${value.message}` : '')
  }
  return `分叉失败：${value.error ?? 'UNKNOWN'}${value.message ? ` — ${value.message}` : ''}`
}

/**
 * @param {object} ctx cordis context; captures `agents` and (optionally)
 *   `workspaceRegistry` via lazy ctx.inject — the same surfaces the official
 *   fork RPC uses. Lazy capture because accessing an un-injected service
 *   property on the cordis context proxy THROWS, and the plugin must stay
 *   loadable in profiles that lack either service.
 * @param {{ randomId?: () => string }} [di] injectable id factory for tests
 */
export function defineForkSessionTool(ctx, { randomId = () => `session-${randomUUID()}` } = {}) {
  let agents = null
  let workspaceRegistry = null
  try {
    ctx.inject?.(['agents'], (scoped) => { agents = scoped.agents })
  } catch { /* hosts without the lazy-inject API */ }
  try {
    ctx.inject?.(['workspaceRegistry'], (scoped) => { workspaceRegistry = scoped.workspaceRegistry })
  } catch { /* hosts without the lazy-inject API */ }
  return {
    name: 'fork_session',
    description:
      '分叉当前会话：以最近一个已完成回合为边界创建子会话，子会话继承到此为止的全部上下文，当前会话不受影响。' +
      '当用户想在保留现状的同时尝试另一个方向（"分个叉试试"/"换个思路重来但不丢上下文"）时调用。无需参数。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: FORK_RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: renderResult(value) }],
    },
    timeoutMs: 30_000,
    isConcurrencySafe: () => false,
    async execute(_args, exec) {
      const session = exec?.agent?.session
      if (session === undefined || session === null) {
        return { ok: false, error: 'NO_AGENT', message: 'fork_session 只能在有活动 agent 的会话中调用' }
      }
      if (agents === null) {
        return { ok: false, error: 'AGENTS_UNAVAILABLE', message: 'agents 服务尚未就绪，稍后重试' }
      }

      const events = Array.isArray(session.events) ? session.events : []
      const boundary = computeForkBoundary(events)
      if (boundary === null) {
        return { ok: false, error: 'NO_COMPLETED_TURN', message: '当前会话还没有已完成的回合，没有可分叉的边界' }
      }

      const childSessionId = randomId()
      const meta = { parentSession: session.id, seedLength: boundary.cut }
      if (typeof session.header?.cwd === 'string') meta.cwd = session.header.cwd
      if (typeof session.header?.agentPreset === 'string') meta.agentPreset = session.header.agentPreset

      try {
        await agents.create({ sessionId: childSessionId, seed: events.slice(0, boundary.cut), meta })
      } catch (error) {
        return { ok: false, error: 'CREATE_FAILED', message: String(error?.message ?? error) }
      }

      // The child is already published when attach fails (same contract as the
      // official fork RPC), so attach issues only annotate the result.
      let warning
      try {
        const workspace = workspaceRegistry?.list?.()
          .find((ws) => Array.isArray(ws.sessionIds) && ws.sessionIds.includes(session.id))
        if (workspace !== undefined) await workspace.attachSession(childSessionId)
      } catch (error) {
        warning = `子会话已创建，但挂回工作区失败：${String(error?.message ?? error)}`
      }
      return warning === undefined
        ? { ok: true, childSessionId, seedLength: boundary.cut }
        : { ok: true, childSessionId, seedLength: boundary.cut, message: warning }
    },
  }
}
