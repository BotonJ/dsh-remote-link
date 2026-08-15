/**
 * In-memory fixed-window rate limiting for the gateway, after MiMo's
 * rate-limit.ts: a plain Map, per-key counters, lazy sweep. Two independent
 * budgets: overall request rate per client IP, and a stricter ban for clients
 * that keep failing authentication (brute-force damping).
 */

const SWEEP_INTERVAL_MS = 60_000

function shouldSweep(state, now) {
  if (now - state.lastSweep < SWEEP_INTERVAL_MS) return false
  state.lastSweep = now
  return true
}

export function createRateLimiter({ windowMs = 60_000, max = 300, now = () => Date.now() } = {}) {
  const entries = new Map() // key -> { count, resetAt }
  const sweepState = { lastSweep: 0 }
  return {
    check(key) {
      const t = now()
      let entry = entries.get(key)
      if (entry === undefined || t >= entry.resetAt) {
        entry = { count: 0, resetAt: t + windowMs }
        entries.set(key, entry)
      }
      entry.count += 1
      if (shouldSweep(sweepState, t)) {
        for (const [k, e] of entries) {
          if (t >= e.resetAt) entries.delete(k)
        }
      }
      const allowed = entry.count <= max
      return { allowed, remaining: Math.max(0, max - entry.count), retryAfterMs: entry.resetAt - t }
    },
  }
}

export function createFailureBan({ windowMs = 300_000, max = 10, banMs = 300_000, now = () => Date.now() } = {}) {
  const entries = new Map() // key -> { count, windowStart, bannedUntil }
  const sweepState = { lastSweep: 0 }
  return {
    isBanned(key) {
      const t = now()
      const entry = entries.get(key)
      const bannedUntil = entry?.bannedUntil ?? 0
      const banned = t < bannedUntil
      if (shouldSweep(sweepState, t)) {
        for (const [k, e] of entries) {
          if (t >= (e.bannedUntil ?? 0) && t - e.windowStart >= windowMs) entries.delete(k)
        }
      }
      return { banned, retryAfterMs: banned ? bannedUntil - t : 0 }
    },
    recordFailure(key) {
      const t = now()
      let entry = entries.get(key)
      if (entry === undefined) {
        entry = { count: 0, windowStart: t, bannedUntil: 0 }
        entries.set(key, entry)
      }
      if (t < entry.bannedUntil) return // already banned; keep the original ban end
      if (t - entry.windowStart >= windowMs) {
        entry.count = 0
        entry.windowStart = t
      }
      entry.count += 1
      if (entry.count >= max) {
        entry.bannedUntil = t + banMs
        entry.count = 0
      }
    },
    recordSuccess(key) {
      const entry = entries.get(key)
      if (entry !== undefined) entry.count = 0
    },
  }
}
