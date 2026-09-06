# remote-watchdog

Watches the remote model box (`macbook-claw`) **from this Mac** and publishes one
JSON file for anything that wants to display its state.

It runs here rather than on the box because a watchdog on the machine it watches
can only ever restart a process — it goes quiet in the case that matters most,
which is the box being off, asleep, or off the network. Running it here makes
"the remote is unreachable" an observation this machine can act on.

## The three states

`GET /v1/models` is not a health check. Measured 2026-09-06, it answered HTTP 200
in 52 ms while every `POST /v1/chat/completions` hung past 120 s: the HTTP layer
outlives the inference loop, so a liveness probe on the model list reports "up"
during exactly the outage this exists to catch. The watchdog therefore asks for a
real token, and the two checks together give:

| status | model list | completion | meaning |
|---|---|---|---|
| `up` | — | answers | serving |
| `wedged` | answers | hangs or errors | process alive, inference stuck |
| `down` | no answer | no answer | box off, asleep, or off the network |

## The probe is a real classification

There are two cold starts and the keepalive has to beat both:

- **weights evicted from GPU memory** — 17 s on that box for the first request.
- **the classifier's ~3.2k-token system prompt evicted from the server's prompt
  cache** — a full prefill instead of the ~15 tokens a warm call prefills, which
  is where every latency outlier in the shadow corpus came from.

A throwaway "reply OK" only fixes the first. It shares no prefix with a real
classification, so it warms nothing the classifier will hit, and on a small
`--prompt-cache-size` it can evict the entry that mattered. The probe therefore
imports the classifier and sends its own system prompt through its own request
path, in the shape the cascade's PRIMARY uses — whole answer, logprobs on. That
is also the exact request that hung on 2026-09-06, which a lighter probe would
have missed.

The state file reports `warmed` so this is never assumed: `true` means the prompt
prefix is hot, `false` means the weights are resident but the next real
classification still pays a full prefill. It also reports the probe's `verdict`
and `pSafe` — a null `pSafe` means the server answered but returned no usable
logprobs, which would make every primary verdict uncertain and quietly route
every command to the secondary.

If the classifier module cannot be imported the watchdog degrades to a plain
liveness probe (`warmed: false`) rather than stopping: a watchdog that stops
watching over a bad path is useless.

## State file

`~/.local/share/cc-local-classifier/remote-watchdog.json`, rewritten atomically
every 60 s. A rolling history of one line per probe is in
`remote-watchdog.jsonl` beside it.

```json
{
  "updated":   "2026-09-06T13:38:25.923Z",
  "target":    "macbook-claw",
  "status":    "up | wedged | down",
  "observed":  "what this probe saw, before the failure threshold is applied",
  "via":       "lan | tailscale | null",
  "endpoint":  "http://192.168.50.16:8080/v1",
  "latencyMs": 812,
  "warmed":    true,
  "verdict":   "SAFE",
  "pSafe":     1.0000122,
  "consecutiveFailures": 0,
  "since":     "when the current status began",
  "lastOk":    "last successful completion",
  "lastError": "lan:timeout tailscale:timeout",
  "probes":    [ { "name": "lan", "liveness": "ok", "completion": "timeout" } ]
}
```

`status` is damped and `observed` is not: three consecutive bad probes are needed
to flip to `wedged` or `down`, because the box is on Wi-Fi and one dropped request
is not an outage. Recovery is deliberately **not** damped — one good answer means
it is serving, and making a UI wait three minutes to say so is worse than useless.
Read `status` for display and `observed` if you want the raw probe.

Endpoints are tried in order and the first to answer wins: LAN first because it is
milliseconds away when it works, Tailscale second because it is the one that still
works away from home. `via` says which, and the distinction is worth surfacing —
"up over Tailscale" says something different about where the laptop is.

## Notifications

A macOS banner fires on a status **change** only, never on every probe, via
`osascript`. A failure to post one is swallowed: a watchdog that cannot draw a
banner still has to write its state file.

## One assumption to re-check

An empty completion is counted as a wedge. On `mlx_lm.server`, which is what the
box runs, an empty answer really is a failure. On an **mtplx**-served endpoint it
is not: a zero-token HTTP 200 is how mtplx replies while a named session is still
generating, and pointing this watchdog at one would make it report `wedged` under
ordinary load. Confirm before reusing it against mtplx.

## Restarting the box

Off until configured. The original plan had the watchdog kill and relaunch after
three failures; that still holds, it just reaches the box over ssh from here.

It refuses to act unless BOTH `restart.ssh` and `restart.command` are set,
because only the box knows how its server is started — a default that guessed
(`pkill -f mlx_lm.server`) would kill the process and leave nothing to bring it
back. It also only fires on a **settled** bad status (three consecutive
failures, not one blip), writes the state file before attempting anything so a
hanging restart cannot cost the UI its reading, and honours `minIntervalMs`
(10 min default) between attempts — a wedge that returns straight after a
restart is not a problem a restart solves.

Every decline is recorded rather than silently skipped, in `state.restart`:

```json
"restart": { "attempted": false, "skipped": "disabled | unconfigured | cooling down" }
```

To enable, in `~/.config/cc-local-classifier/remote-watchdog.json`:

```json
{ "restart": {
    "enabled": true,
    "ssh": "<user>@macbook-claw.local",
    "command": "launchctl kickstart -k gui/$(id -u)/<the server's launchd label>"
} }
```

The ssh key must already be authorized on the box; the watchdog uses
`BatchMode=yes` and will never prompt.

## Configuration

Optional, at `~/.config/cc-local-classifier/remote-watchdog.json`. Any subset of
the defaults: `target`, `endpoints` (`[{name, url}]`), `model`,
`livenessTimeoutMs` (5000), `completionTimeoutMs` (25000), `failureThreshold` (3),
`notify` (true).

## Running

Installed as the launchd agent `com.khalic.remote-watchdog`, every 60 s, logging
to `/tmp/remote-watchdog.log`. Run it by hand with:

    node packages/remote-watchdog/remote-watchdog.mjs
