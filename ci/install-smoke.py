#!/usr/bin/env python3
"""Linux lifecycle/TTY regression checks; all installs and data use a tempdir.

Run after cargo build: python3 ci/install-smoke.py
Uses the workspace debug cache; --profile release exercises the documented build.
"""

import argparse
import errno
import hashlib
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import time


PASSWORD = "InstallSmoke-7q!R2#vL9"


def run(args, env, expected=0):
    start = time.monotonic()
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=180)
    if result.returncode != expected:
        raise AssertionError(
            f"{args}: exit {result.returncode}, expected {expected}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    print(f"PASS {Path(str(args[0])).name} {' '.join(args[1:])} ({time.monotonic() - start:.2f}s)", flush=True)
    return result.stdout


def snapshot(root):
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def terminal_run(binary, args, env, responses, expected):
    """Drive the actual hidden-input prompts through a controlling terminal.

    Responses are sent only after their prompt; failures kill/reap the child
    before TemporaryDirectory removes its owned files. Never log passwords.
    """
    child, fd = pty.fork()
    if child == 0:
        try:
            os.execve(binary, [binary, *args], env)
        except OSError:
            # Do not unwind inherited TemporaryDirectory owners in the child.
            os._exit(127)
    output = b""
    pending = list(responses)
    status = None
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if pending and pending[0][0] in output:
                _, response = pending.pop(0)
                os.write(fd, response.encode() + b"\n")
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output += chunk
        else:
            raise AssertionError("TTY prompt timed out")
        _, status = os.waitpid(child, 0)
        assert not pending, "setup exited before requesting password confirmation"
        assert os.waitstatus_to_exitcode(status) == expected, "unexpected setup exit status"
        assert PASSWORD.encode() not in output, "password was echoed"
        return output
    finally:
        if status is None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        os.close(fd)


def check_setup(binary, base, env):
    env = env.copy()
    env.pop("PQ_DIARY_PASSWORD", None)
    first = (b"Password: ", PASSWORD)
    confirmation = b"Confirm new password: "
    for command in ("init", "vault"):
        home = base / f"tty-{command}"
        env["PQ_DIARY_HOME"] = str(home)
        collection = base / f"collection-{command}"
        args = (
            ["init"] if command == "init"
            else ["--vault", str(collection), "vault", "create", "test"]
        )
        weak_prompt = b"Use this weak password anyway? [y/N]: "
        # Preserve the existing weak-password decision before confirmation.
        output = terminal_run(
            binary, args, env, [(b"Password: ", "short"), (weak_prompt, "n")], 0,
        )
        assert confirmation not in output
        assert not home.exists() and not collection.exists()
        terminal_run(
            binary, args, env,
            [(b"Password: ", "short"), (weak_prompt, "y"), (confirmation, "different")], 1,
        )
        assert not home.exists() and not collection.exists()
        # Mismatch must fail before creating config, collection, or vault.
        output = terminal_run(binary, args, env, [first, (confirmation, "different")], 1)
        assert b"Passwords do not match" in output
        assert not home.exists() and not collection.exists()
        terminal_run(binary, args, env, [first, (confirmation, PASSWORD)], 0)
        vault = home / "vaults/default" if command == "init" else collection / "test"
        readable = env.copy()
        readable["PQ_DIARY_PASSWORD"] = PASSWORD
        run([binary, "--vault", str(vault), "list"], readable)
        before = snapshot(home if command == "init" else vault)
        # A failed confirmation must not alter an already-existing vault.
        if command == "vault":
            terminal_run(binary, args, env, [first, (confirmation, "different")], 1)
            assert snapshot(vault) == before
        else:
            terminal_run(binary, args, env, [], 1)
            assert snapshot(home) == before
        print(f"PASS {command}: confirmation mismatch preserves state; matching password unlocks")
    full = base / "full-policy-collection"
    output = terminal_run(
        binary, ["--vault", str(full), "vault", "create", "test", "--policy", "full"], env,
        [("本当に許可しますか？ [y/N]: ".encode(), "n")], 0,
    )
    assert b"Password: " not in output and confirmation not in output
    assert not full.exists()
    print("PASS policy and weak-password decisions precede secret confirmation")


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("debug", "release"), default="debug")
    parser.add_argument("--setup-binary", help="Only run TTY regressions against this binary")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pq-diary-install-") as temporary:
        base = Path(temporary)
        env = os.environ.copy()
        env.pop("PQ_DIARY_PASSWORD", None)
        env["PQ_DIARY_HOME"] = str(base / "app")
        if options.setup_binary:
            check_setup(str(Path(options.setup_binary).resolve()), base, env)
            print(f"PASS TTY regressions ({time.monotonic() - started:.2f}s total)")
            return
        env["PQ_DIARY_PASSWORD"] = PASSWORD
        root = base / "cargo-root"
        binary = str(root / "bin/pq-diary")
        install = ["cargo", "install", "--path", "cli", "--locked", "--offline", "--root", str(root)]
        if options.profile == "debug":
            install.append("--debug")
        run(install, env)
        run([binary, "--version"], env)
        run([binary, "init"], env)
        run([binary, "new", "install-smoke-entry", "--body", "synthetic smoke body"], env)
        home = Path(env["PQ_DIARY_HOME"])
        before = snapshot(home)
        unrelated = root / "bin/unrelated"
        unrelated.write_text("preserve unrelated file")
        run(install, env)
        assert snapshot(home) == before
        run(["cargo", "uninstall", "pq-diary", "--root", str(root)], env)
        assert not Path(binary).exists()
        assert unrelated.read_text() == "preserve unrelated file"
        assert snapshot(home) == before
        run(install, env)
        assert "install-smoke-entry" in run([binary, "list"], env)
        run([binary, "init"], env, expected=1)
        assert snapshot(home) == before
        conflict = base / "conflict"
        (conflict / "bin").mkdir(parents=True)
        foreign = conflict / "bin/pq-diary"
        foreign.write_text("foreign executable")
        conflicting_install = install.copy()
        conflicting_install[conflicting_install.index("--root") + 1] = str(conflict)
        run(conflicting_install, env, expected=101)
        assert foreign.read_text() == "foreign executable"
        check_setup(binary, base, env)
        run(["cargo", "uninstall", "pq-diary", "--root", str(root)], env)
        assert snapshot(home) == before
        assert unrelated.read_text() == "preserve unrelated file"
        print("PASS lifecycle: application data and unrelated/conflicting files preserved")
    print(f"PASS install smoke ({time.monotonic() - started:.2f}s total)")


if __name__ == "__main__":
    main()
