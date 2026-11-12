"""Cross sudo's terminal boundary before detaching the privileged worker."""

import json
import os
import select
import signal
import subprocess
import sys
import time


def redact(message, sessions):
    for session in sessions.values():
        cookie = session.get("COOKIE")
        if cookie:
            message = message.replace(cookie, "<REDACTED>")
    return message


def detach_output():
    # The startup handshake is complete; terminal closure must not affect logging.
    with open(os.devnull, "wb") as null:
        os.dup2(null.fileno(), 1)
        os.dup2(null.fileno(), 2)


def launch_worker(payload, runner, timeout=15):
    process = subprocess.Popen(
        [sys.executable, runner, "_daemon"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    output, errors = bytearray(), bytearray()
    try:
        process.stdin.write(json.dumps(payload).encode())
        process.stdin.close()
        deadline = time.monotonic() + timeout
        streams = [process.stdout, process.stderr]
        while time.monotonic() < deadline:
            ready, _, _ = select.select(streams, [], [], 0.1)
            for stream in ready:
                part = os.read(stream.fileno(), 4096)
                if not part:
                    streams.remove(stream)
                    continue
                target = output if stream is process.stdout else errors
                target.extend(part)
                if len(target) > 8192:
                    raise RuntimeError("Controller startup output exceeded its limit.")
            if b"\n" in output:
                message = json.loads(output.split(b"\n", 1)[0])
                if message != {"ready": True}:
                    raise RuntimeError("Invalid controller startup handshake.")
                return process
            if not streams:
                detail = errors.decode(errors="replace").strip()
                detail = redact(detail, payload.get("sessions", {}))
                raise RuntimeError(detail or "Controller worker exited before initialization.")
        raise RuntimeError("Controller initialization timed out.")
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
