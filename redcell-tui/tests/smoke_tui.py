#!/usr/bin/env python3
"""Drive the real TUI with tmux, isolated storage, and no network operations."""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/redcell-tui")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    if not binary.is_file():
        parser.error("Build the TUI first: cargo build --release")

    with tempfile.TemporaryDirectory(prefix="redcell-tui-smoke-") as tmp:
        root = Path(tmp)
        socket = str(root / "tmux.sock")

        def tmux(*command, input=None):
            return subprocess.run(
                ["tmux", "-S", socket, *command], input=input,
                text=True, capture_output=True, check=True,
            ).stdout

        def wait_for(label, condition):
            deadline = time.monotonic() + 6
            last = ""
            stable = ""
            stable_since = time.monotonic()
            while time.monotonic() < deadline:
                last = tmux("capture-pane", "-p", "-t", "ui")
                if last != stable:
                    stable = last
                    stable_since = time.monotonic()
                # tmux resizes its buffer before the app redraws. A matching
                # old/cropped frame is not evidence of the responsive layout.
                if condition(last.replace(" ", "")) and time.monotonic() - stable_since >= 0.25:
                    return last
                time.sleep(0.05)
            raise AssertionError(f"{label}: screen did not reach expected state\n{last}")

        def capture(name, condition):
            shot = wait_for(name, condition)
            (args.output / f"{name}.txt").write_text(shot)
            print(f"PASS {name}", flush=True)
            return shot

        def keys(*values):
            tmux("send-keys", "-t", "ui", *values)

        def text(value):
            tmux("send-keys", "-l", "-t", "ui", value)

        command = shlex.join([
            "env", "-i", f"HOME={root}", f"XDG_DATA_HOME={root / 'data'}",
            f"REDCELL_HOME={root / 'config'}", f"PATH={os.environ['PATH']}",
            "TERM=xterm-256color", "LANG=C.UTF-8", str(binary),
        ])
        tmux("new-session", "-d", "-s", "ui", "-x", "110", "-y", "32", command)
        try:
            capture("01-welcome", lambda s: "시작하기" in s and "/setup" in s)
            text("/")
            shot = capture("02-command-menu", lambda s: "명령어1/11" in s and ">/sweep" in s)
            assert shot.index("❯ /") < shot.index("명령어 1/11")
            keys("C-u")
            text("/설정")
            capture("03-korean-search", lambda s: ">/setup" in s and "❯/설정" in s)
            keys("C-u")
            text("/say")
            keys("Enter")
            capture("04-argument-edit", lambda s: "❯/say" in s and "명령어1/" not in s)
            text("이력 메모")
            keys("Enter")
            capture("05-memo", lambda s: "[you]이력메모" in s)
            text("작성 중인 초안")
            keys("Up")
            wait_for("history", lambda s: "❯/say이력메모" in s)
            keys("Down")
            wait_for("draft restored", lambda s: "❯작성중인초안" in s)
            keys("C-p")
            wait_for("palette", lambda s: "명령어1/11" in s)
            keys("Escape")
            capture("06-draft-restored", lambda s: "❯작성중인초안" in s)
            keys("C-c")
            tmux("load-buffer", "-", input="/say 첫 줄\n둘째 줄")
            tmux("paste-buffer", "-p", "-t", "ui")
            capture("07-paste-not-executed", lambda s: "❯/say첫줄" in s and "둘째줄" in s)
            sessions = list((root / "data" / "redcell-tui" / "sessions").glob("*.json"))
            assert sessions and "첫 줄" not in sessions[0].read_text()
            keys("Enter")
            wait_for("paste submitted explicitly", lambda s: "[you]첫줄" in s)
            for width, height in [(80, 24), (48, 16), (24, 8)]:
                keys("C-u")
                text("/")
                tmux("resize-window", "-t", "ui", "-x", str(width), "-y", str(height))
                keys("Up")
                capture(f"08-menu-{width}x{height}", lambda s: "명령어11/11" in s and ">/quit" in s)
            tmux("resize-window", "-t", "ui", "-x", "80", "-y", "24")
            keys("C-u")
            text("/setup")
            keys("Enter")
            capture("09-setup", lambda s: "host/URL" in s and "Ctrl+S저장" in s)
            keys("C-s")
            wait_for("form saved", lambda s: "host/URL" not in s)
            text("/providers")
            keys("Enter")
            capture("10-onboarding", lambda s: "설정마법사" in s)
            keys("Escape")
            wait_for("onboarding skipped", lambda s: "설정마법사" not in s)
            keys("C-q")
        finally:
            subprocess.run(["tmux", "-S", socket, "kill-server"], capture_output=True)
    print(f"Screens saved to {args.output}", flush=True)


if __name__ == "__main__":
    main()
