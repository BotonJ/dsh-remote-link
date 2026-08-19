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

export function createNotifier({ barkUrl = '', ntfyUrl = '', webhookUrl = '', fetchImpl = globalThis.fetch?.bind(globalThis), log = () => {} } = {}) {
  const channels = []
  if (barkUrl !== '') channels.push(['bark', async ({ title, body }) => {
    await fetchImpl(`${barkUrl.replace(/\/$/, '')}/${encodeURIComponent(title)}/${encodeURIComponent(body)}`)
  }])
  if (ntfyUrl !== '') channels.push(['ntfy', async ({ title, body }) => {
    await fetchImpl(ntfyUrl, { method: 'POST', headers: { title }, body })
  }])
  if (webhookUrl !== '') channels.push(['webhook', async (payload) => {
    await fetchImpl(webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...payload, at: Date.now() }),
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
