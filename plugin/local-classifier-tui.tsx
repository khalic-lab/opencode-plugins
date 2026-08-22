/** @jsxImportSource @opentui/solid */
/**
 * The classifier's box in the TUI: what it decided about the permission on
 * screen, and how long you have before it answers for you.
 *
 * This is a TUI plugin, which is a different kind from the classifier itself —
 * a module exports `server` or `tui`, never both — so it registers separately,
 * in `tui.json` rather than `opencode.json`:
 *
 *   { "$schema": "https://opencode.ai/tui.json",
 *     "plugin": ["file:///Users/…/.config/opencode/local-classifier/local-classifier-tui.tsx"] }
 *
 * The `.tsx` is not a build step. opencode transpiles the file itself, and the
 * bare `@opentui`/`solid-js` specifiers below resolve through a Bun plugin the
 * host installs for exactly this purpose. Two caveats, both measured on
 * 1.18.15: the specifiers resolve only as STATIC imports — a dynamic `import()`
 * of the same string throws "Cannot find module" — and the file must carry an
 * `id`, since the TUI loader has no legacy fallback for one that lacks it and
 * drops the plugin with only a log line to show for it.
 *
 * Everything worth testing lives in ./tui-view.js; this file only subscribes,
 * ticks, and draws.
 */
import { createSignal, Show } from "solid-js"
import os from "node:os"
import path from "node:path"
import { emptyState, apply, view, createTailer, HOLD_MS } from "./tui-view.js"

/**
 * Four times a second. The countdown only changes at 1 Hz, but the log is also
 * this box's event bus, and a poll slower than the eye would make the box
 * appear noticeably after the prompt it describes.
 */
const POLL_MS = 250

const DEFAULT_LOG_DIR = path.join(os.homedir(), ".local", "share", "opencode-local-classifier", "logs")

/**
 * Same scheme as the toasts: amber is the only state with a clock running,
 * blue means the prompt is simply still yours, red means something broke.
 */
const TONE = { pending: "secondary", countdown: "warning", risky: "info", failed: "error", done: "success" }
const MARK = { pending: "◇", countdown: "⏱", risky: "✋", failed: "✗", done: "✓" }

const same = (a, b) =>
  a === b ||
  (!!a &&
    !!b &&
    a.id === b.id &&
    a.tone === b.tone &&
    a.headline === b.headline &&
    a.command === b.command &&
    a.detail === b.detail)

export default {
  id: "local-classifier-tui",
  tui: async (api, options) => {
    const dir = typeof options?.logDir === "string" ? options.logDir : DEFAULT_LOG_DIR
    // How long a finished permission lingers. Settable because "long enough to
    // read" is a property of the reader, not of the plugin.
    const holdMs = Number.isFinite(options?.holdMs) && options.holdMs > 0 ? options.holdMs : HOLD_MS
    const tailer = createTailer({ dir })
    const [shown, setShown] = createSignal(null)
    let state = emptyState()

    const timer = setInterval(() => {
      const now = Date.now()
      for (const record of tailer.poll()) state = apply(state, record, now)
      const next = view(state, now, holdMs)
      // Only when the words change: setting the signal on every tick would
      // re-render the box four times a second to say the same thing.
      if (!same(shown(), next)) setShown(next)
    }, POLL_MS)
    api.lifecycle.onDispose(() => clearInterval(timer))

    api.slots.register({
      order: 0,
      slots: {
        app_bottom(ctx) {
          const skin = ctx.theme.current
          return (
            <Show when={shown()} keyed>
              {(v) => (
                <box
                  border
                  borderColor={skin[TONE[v.tone]]}
                  title=" local-classifier "
                  titleColor={skin[TONE[v.tone]]}
                  titleAlignment="left"
                  paddingLeft={1}
                  paddingRight={1}
                  flexDirection="column"
                  width="100%"
                >
                  <text fg={skin[TONE[v.tone]]}>{`${MARK[v.tone]}  ${v.headline}`}</text>
                  <Show when={v.command}>
                    <text fg={skin.text}>{`   ${v.command}`}</text>
                  </Show>
                  <Show when={v.detail}>
                    <text fg={skin.secondary}>{`   ${v.detail}`}</text>
                  </Show>
                </box>
              )}
            </Show>
          )
        },
      },
    })
  },
}
