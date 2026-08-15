import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computeForkBoundary, defineForkSessionTool } from '../src/fork-session.js'

const ev = (seq, type) => ({ seq, type })

function events() {
  return [
    ev(0, 'session/start'),
    ev(1, 'turn/start'),
    ev(2, 'message'),
    ev(3, 'turn/end'),
    ev(4, 'session/title'),
    ev(5, 'turn/start'),
    ev(6, 'message'),
  ]
}

test('computeForkBoundary: last completed turn, extended through trailing out-of-band events', () => {
  assert.deepEqual(computeForkBoundary(events()), { boundarySeq: 3, cut: 5 })
})

test('computeForkBoundary: log ending exactly at turn/end cuts right after it', () => {
  const only = [ev(0, 'turn/start'), ev(1, 'message'), ev(2, 'turn/end')]
  assert.deepEqual(computeForkBoundary(only), { boundarySeq: 2, cut: 3 })
})

test('computeForkBoundary: no completed turn means no fork', () => {
  assert.equal(computeForkBoundary([ev(0, 'turn/start'), ev(1, 'message')]), null)
  assert.equal(computeForkBoundary([]), null)
})

// ---- tool definition ----

function fakeCtx() {
  const created = []
  const registered = []
  const workspaceRegistry = {
    attached: null,
    list: () => [{ id: 'ws-1', sessionIds: ['session-parent'], attachSession: async (id) => { workspaceRegistry.attached = id } }],
  }
  const agents = {
    async create(options) { created.push(options); return { agent: {}, dispose: async () => {} } },
  }
  return {
    registered,
    tools: { register(def) { registered.push(def) } },
    // lazy-inject stand-in: fires immediately with the captured services
    inject(names, cb) { cb({ agents, workspaceRegistry }) },
    // exposed for tests to override behavior on the same captured instances
    agents,
    workspaceRegistry,
    created,
  }
}

function fakeExec(session) {
  return { signal: undefined, agent: session ? { session } : undefined, token: 'test' }
}

const SESSION = {
  id: 'session-parent',
  header: { id: 'session-parent', cwd: '/work/project', agentPreset: 'standard' },
  events: events(),
}

function registerTool(ctx) {
  const tool = defineForkSessionTool(ctx, { randomId: () => 'session-child-1' })
  ctx.tools.register(tool)
  return tool
}

test('tool registers under the name fork_session with no required parameters', () => {
  const ctx = fakeCtx()
  const tool = registerTool(ctx)
  assert.equal(ctx.registered.length, 1)
  assert.equal(tool.name, 'fork_session')
  assert.deepEqual(tool.parameters.required ?? [], [])
  assert.equal(typeof tool.execute, 'function')
})

test('execute forks the current session: seeds a child through agents.create and attaches the workspace', async () => {
  const ctx = fakeCtx()
  const tool = registerTool(ctx)
  const result = await tool.execute({}, fakeExec(SESSION))
  assert.deepEqual(result, { ok: true, childSessionId: 'session-child-1', seedLength: 5 })
  assert.equal(ctx.created.length, 1)
  const options = ctx.created[0]
  assert.equal(options.sessionId, 'session-child-1')
  assert.equal(options.seed.length, 5)
  assert.deepEqual(options.meta, { parentSession: 'session-parent', seedLength: 5, cwd: '/work/project', agentPreset: 'standard' })
  assert.equal(ctx.workspaceRegistry.attached, 'session-child-1')
})

test('execute reports NO_AGENT when called outside an agent session', async () => {
  const ctx = fakeCtx()
  const tool = registerTool(ctx)
  const result = await tool.execute({}, fakeExec(null))
  assert.equal(result.ok, false)
  assert.equal(result.error, 'NO_AGENT')
  assert.equal(ctx.created.length, 0)
})

test('execute reports NO_COMPLETED_TURN for a session without completed turns', async () => {
  const ctx = fakeCtx()
  const tool = registerTool(ctx)
  const session = { id: 's', header: {}, events: [ev(0, 'turn/start')] }
  const result = await tool.execute({}, fakeExec(session))
  assert.equal(result.ok, false)
  assert.equal(result.error, 'NO_COMPLETED_TURN')
})

test('execute surfaces agents.create failures without throwing', async () => {
  const ctx = fakeCtx()
  ctx.agents.create = async () => { throw new Error('boom') }
  const tool = registerTool(ctx)
  const result = await tool.execute({}, fakeExec(SESSION))
  assert.equal(result.ok, false)
  assert.equal(result.error, 'CREATE_FAILED')
  assert.match(result.message, /boom/)
})

test('execute still succeeds when workspace attach fails', async () => {
  const ctx = fakeCtx()
  ctx.workspaceRegistry.list = () => [{ id: 'ws', sessionIds: ['session-parent'], attachSession: async () => { throw new Error('attach blew up') } }]
  const tool = registerTool(ctx)
  const result = await tool.execute({}, fakeExec(SESSION))
  assert.equal(result.ok, true)
  assert.match(result.message, /attach blew up/)
})

test('execute degrades gracefully when the agents service never arrives', async () => {
  const lateCtx = {
    registered: [],
    tools: { register(def) { this.registered.push(def) } },
    inject() { /* service never appears */ },
  }
  const tool = defineForkSessionTool(lateCtx, { randomId: () => 'x' })
  const result = await tool.execute({}, fakeExec(SESSION))
  assert.equal(result.ok, false)
  assert.equal(result.error, 'AGENTS_UNAVAILABLE')
})

test('render tolerates null and describes successful forks', () => {
  const ctx = fakeCtx()
  const tool = registerTool(ctx)
  assert.doesNotThrow(() => tool.output.render({}, null))
  const blocks = tool.output.render({}, { ok: true, childSessionId: 'session-child-1', seedLength: 5 })
  assert.equal(blocks[0].type, 'text')
  assert.match(blocks[0].text, /session-child-1/)
  const fail = tool.output.render({}, { ok: false, error: 'NO_AGENT', message: 'x' })
  assert.match(fail[0].text, /NO_AGENT/)
})
