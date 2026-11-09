#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run an interactive shell on a pseudo-terminal and type lines into it.

Usage: pty-drive.py <input-file> <command> [args...]

Some shells only run their command hooks when they read a terminal:
fish fires fish_preexec and fish_postexec only from its interactive
reader. This driver gives the shell a pty, answers the terminal queries
a shell may block on at startup (primary device attributes, cursor
position), and types each line of <input-file> once the shell's output
has been quiet for a moment, so a line is never read as a query reply.
The shell's output is copied to stdout. Exits with the shell's status,
or 124 if it is still running after the overall timeout.
"""

import os
import pty
import select
import sys
import time

QUIET = 0.8  # seconds of no output before the next line is typed
TIMEOUT = 120  # seconds for the whole session

# Queries and the replies a plain VT220-class terminal gives.
REPLIES = [
    (b"\x1b[0c", b"\x1b[?62;22c"),
    (b"\x1b[c", b"\x1b[?62;22c"),
    (b"\x1b[6n", b"\x1b[1;1R"),
]


def main():
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    with open(sys.argv[1], "rb") as f:
        lines = [line.rstrip(b"\n") + b"\r" for line in f if line.strip()]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(sys.argv[2], sys.argv[2:])
    start = time.monotonic()
    last_output = time.monotonic()
    pending = b""
    status = None
    while True:
        if time.monotonic() - start > TIMEOUT:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            return 124
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                data = os.read(fd, 4096)
            except OSError:
                data = b""
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
            last_output = time.monotonic()
            pending = (pending + data)[-64:]
            for query, reply in REPLIES:
                if query in pending:
                    os.write(fd, reply)
                    pending = pending.replace(query, b"")
            continue
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
        if lines and time.monotonic() - last_output >= QUIET:
            os.write(fd, lines.pop(0))
            last_output = time.monotonic()
    if status is None:
        _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
