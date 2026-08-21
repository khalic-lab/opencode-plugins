#!/usr/bin/env python3
"""
End-to-end check that the classifier's TUI box actually paints.

Nothing about the box can be unit-tested — the render function needs opencode's
TUI runtime, which only exists inside opencode. So this drives the real thing:
it starts opencode on a pty, appends synthetic classifier log lines to a
throwaway log dir while it runs, and reads the escape-code stream back to see
what was drawn. The classifier itself is not involved; this tests the box.

Reading a TUI's output is not reading a transcript. opencode repaints only the
cells that changed, so a line drawn once never appears again in the stream even
though it is still on screen, and the countdown arrives as a bare digit
overwriting one column. Assertions here are unordered, and the countdown is
checked as the digits 5,4,3,2,1 rather than as another full sentence.

Usage: python3 eval/tui-e2e.py
Exit 0 if every expected string was painted, 1 otherwise. Temporarily points
~/.config/opencode/tui.json at its own log dir and restores it afterwards.
"""

import os, pty, fcntl, termios, struct, subprocess, signal, sys, time, select, json, re, shutil, datetime

HOME = os.path.expanduser("~")
TUI_JSON = os.path.join(HOME, ".config", "opencode", "tui.json")
PLUGIN = f"file://{HOME}/.config/opencode/local-classifier/local-classifier-tui.tsx"
LOGDIR = "/tmp/lc-tui-e2e/logs"
NOTE = "/tmp/lc-tui-e2e.log"
CWD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PERMISSION_ID = "per_e2e_1"


def note(s):
    with open(NOTE, "a") as f:
        f.write(s + "\n")
    print(s, flush=True)


def emit(rec):
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    rec = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "plugin": "local-classifier", "v": "0.1.0", "mode": "enforce", **rec,
    }
    with open(os.path.join(LOGDIR, f"events-{day}.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")
    note(f"  emitted {rec['event']}")


SCHEDULE = [
    (8.0, lambda: emit({"event": "permission.received", "permission_id": PERMISSION_ID, "session_id": "s1",
                        "permission": "bash", "metadata": {"command": "git status && git diff"}, "covered": True})),
    (11.0, lambda: emit({"event": "classification", "permission_id": PERMISSION_ID, "session_id": "s1",
                         "permission": "bash", "subject": "git status && git diff", "verdict": "SAFE",
                         "reason": "Both git status and git diff are read-only inspection commands.",
                         "failure": None})),
    (11.3, lambda: emit({"event": "action.countdown", "permission_id": PERMISSION_ID, "session_id": "s1",
                         "countdown_ms": 6000, "verdict": "SAFE"})),
    (18.0, lambda: emit({"event": "action", "permission_id": PERMISSION_ID, "session_id": "s1",
                         "decided": "approved", "countdown_ms": 6000})),
]

WANT = ["local-classifier", "classifying", "auto-approving in 6s",
        "git status && git diff", "read-only inspection commands", "auto-approved"]


def main():
    shutil.rmtree(LOGDIR, ignore_errors=True)
    os.makedirs(LOGDIR, exist_ok=True)
    open(NOTE, "w").close()

    backup = TUI_JSON + ".e2e-backup"
    had = os.path.exists(TUI_JSON)
    if had:
        shutil.copy(TUI_JSON, backup)
    with open(TUI_JSON, "w") as f:
        json.dump({"$schema": "https://opencode.ai/tui.json",
                   "plugin": [[PLUGIN, {"logDir": LOGDIR}]]}, f, indent=2)
    try:
        return run()
    finally:
        if had:
            shutil.move(backup, TUI_JSON)
        else:
            os.remove(TUI_JSON)


def run():
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    p = subprocess.Popen(["opencode"], stdin=slave, stdout=slave, stderr=slave, cwd=CWD,
                         env=dict(os.environ, TERM="xterm-256color"), start_new_session=True)
    os.close(slave)
    note(f"started opencode pid={p.pid}")

    buf = bytearray()
    start = time.time()
    i = 0
    while time.time() - start < 26 and p.poll() is None:
        t = time.time() - start
        while i < len(SCHEDULE) and t >= SCHEDULE[i][0]:
            note(f"t={t:.1f}s")
            SCHEDULE[i][1]()
            i += 1
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            buf += data

    note("terminating")
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    except Exception:
        pass
    time.sleep(1.5)
    if p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            pass

    clean = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\x1b[=>]", "",
                   buf.decode("utf-8", "replace"))
    with open("/tmp/lc-tui-e2e-clean.txt", "w") as f:
        f.write(clean)

    ok = True
    for w in WANT:
        at = clean.find(w)
        note(f"{'FOUND  ' if at >= 0 else 'MISSING'} {w!r}" + (f" @{at}" if at >= 0 else ""))
        if at < 0:
            ok = False

    tail = clean[clean.find("auto-approving in 6s"):] if "auto-approving in 6s" in clean else ""
    at, ticks = 0, []
    for d in "54321":
        at = tail.find(d, at)
        if at < 0:
            break
        ticks.append(d)
        at += 1
    note(f"countdown ticks after the 6s frame: {''.join(ticks) or '(none)'}")
    if len(ticks) < 5:
        ok = False

    note("E2E: PASS" if ok else "E2E: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
