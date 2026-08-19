/**
 * Offline interaction push: best-effort notifications through the user's
 * own channels when the agent is waiting on an approval/question and no
 * browser leg is connected to see it.
 *
 * Policy boundary: notifications carry only "something needs you" plus a
 * non-secret summary — never URLs, pairing secrets, or recovery codes.
 * Channel credentials (Bark key / ntfy topic) live in the user's config and
 * are sent only to those services. All channels are tried in parallel; a
 * failing channel logs and never breaks the others.
 */

export function createNotifier({ barkUrl = '', ntfyUrl = '', webhookUrl = '', fetchImpl = globalThis.fetch?.bind(globalThis), fetchTimeoutMs = 10_000, log = () => {} } = {}) {
  // A hung push endpoint must not pin sockets/promises forever.
  const signal = () => AbortSignal.timeout(fetchTimeoutMs)
  const channels = []
  if (barkUrl !== '') channels.push(['bark', async ({ title, body }) => {
    await fetchImpl(`${barkUrl.replace(/\/$/, '')}/${encodeURIComponent(title)}/${encodeURIComponent(body)}`, { signal: signal() })
  }])
  if (ntfyUrl !== '') channels.push(['ntfy', async ({ title, body }) => {
    // HTTP header values must be Latin-1 and our titles are CJK, so a
    // `title` header makes fetch throw ("Cannot convert argument to a
    // ByteString") on every push. Use the documented JSON publishing route
    // instead: POST {topic, title, message} to the service root derived from
    // the configured topic URL (supports self-hosted subpath deployments and
    // keeps any query params such as access tokens).
    const url = new URL(ntfyUrl)
    const segments = url.pathname.split('/').filter(Boolean)
    const topic = segments.pop() ?? ''
    url.pathname = segments.length === 0 ? '/' : `/${segments.join('/')}/`
    await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ topic, title, message: body }),
      signal: signal(),
    })
  }])
  if (webhookUrl !== '') channels.push(['webhook', async (payload) => {
    await fetchImpl(webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...payload, at: Date.now() }),
      signal: signal(),
    })
  }])

  return {
    get enabled() { return channels.length > 0 },
    channelNames: () => channels.map(([name]) => name),
    async notify(payload) {
      await Promise.all(channels.map(async ([name, send]) => {
        try {
          await send(payload)
        } catch (error) {
          log(`notify: ${name} push failed: ${String(error?.message ?? error)}`)
        }
      }))
    },
  }
}
