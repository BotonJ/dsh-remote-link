import { Flag } from "@/flag/flag"
import { Hono } from "hono"
import { getMimeType } from "hono/utils/mime"
import fs from "node:fs/promises"
import path from "node:path"

const embeddedUIPromise = Flag.MIMOCODE_DISABLE_EMBEDDED_WEB_UI
  ? Promise.resolve(null)
  : // @ts-expect-error - generated file at build time
    import("opencode-web-ui.gen.ts").then((module) => module.default as Record<string, string>).catch(() => null)

const DEFAULT_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; media-src 'self' data:; connect-src 'self' data:"

// CSP used by the lightweight fallback Web UI. We must allow 'unsafe-inline'
// for scripts because the fallback is a single self-contained HTML file with
// inlined JS. The page only talks back to this same origin.
// Note: 'event-src' is NOT a real CSP directive — EventSource connections are
// governed by 'connect-src', so we don't list it.
const FALLBACK_CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'"

export const UIRoutes = (): Hono =>
  new Hono().all("/*", async (c) => {
    const embeddedWebUI = await embeddedUIPromise
    const reqPath = c.req.path

    if (embeddedWebUI) {
      const match = embeddedWebUI[reqPath.replace(/^\//, "")] ?? embeddedWebUI["index.html"] ?? null
      if (!match) return c.json({ error: "Not Found" }, 404)

      if (await fs.exists(match)) {
        const mime = getMimeType(match) ?? "text/plain"
        c.header("Content-Type", mime)
        if (mime.startsWith("text/html")) {
          c.header("Content-Security-Policy", DEFAULT_CSP)
        }
        return c.body(new Uint8Array(await fs.readFile(match)))
      } else {
        return c.json({ error: "Not Found" }, 404)
      }
    } else {
      // Embedded Web UI unavailable (build flag skipEmbedWebUi = true).
      // Serve the lightweight fallback UI from the sibling ui.html file so that
      // QR-code mobile access works out of the box. Bun supports import.meta.dirname
      // natively; in `bun run` (dev) mode this resolves to this source directory.
      try {
        const htmlPath = path.join(import.meta.dirname!, "ui.html")
        const html = await fs.readFile(htmlPath, "utf-8")
        c.header("Content-Type", "text/html; charset=utf-8")
        c.header("Content-Security-Policy", FALLBACK_CSP)
        c.header("Cache-Control", "no-cache")
        return c.body(html)
      } catch (e: any) {
        return c.json(
          {
            error: "Web UI is temporarily unavailable.",
            detail: "Fallback ui.html could not be read: " + String(e?.message ?? e),
          },
          503,
        )
      }
    }
  })
