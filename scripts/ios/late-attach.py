#!/usr/bin/env python3
"""
Late-attach helper for hostile iOS apps that probe for a tracer during startup.

Usage:
    python3 late-attach.py <host:port> <bundle-id> [--wait SECONDS] [--script PATH]

Example:
    python3 late-attach.py 192.168.9.220:27145 com.toyopagroup.picaboo \\
        --wait 12 --script ./hooks.js

Why this exists:
    Apps like Snapchat self-kill when frida attaches *during* their startup
    (a one-shot tracer-presence check). Spawning with frida -f triggers it
    every time, regardless of how phantom-ised the server binary is.

    The workaround: spawn the process, resume it, sleep until startup is
    finished, then attach. The same one-shot guard does not re-run later,
    so the late attach goes through and full Frida instrumentation works.

    This pattern works on both upstream frida-server and ajeossida-server.
    Use it whenever the gadget-tweak path is not an option (e.g. unrooted
    devices, or when you need the standard frida-tools workflow).
"""

import argparse
import sys
import time

import frida


def main():
    p = argparse.ArgumentParser()
    p.add_argument("target", help="frida-server endpoint, e.g. 192.168.0.10:27042")
    p.add_argument("bundle", help="bundle identifier, e.g. com.example.app")
    p.add_argument("--wait", type=float, default=12.0,
                   help="seconds to let the app finish startup before attaching")
    p.add_argument("--script", help="optional JS path to load after attach")
    args = p.parse_args()

    print(f"[+] connecting to {args.target}")
    dev = frida.get_device_manager().add_remote_device(args.target)

    print(f"[+] spawning {args.bundle}")
    pid = dev.spawn([args.bundle])
    print(f"    pid={pid}")

    dev.resume(pid)
    print(f"[+] resumed; sleeping {args.wait}s for startup")
    time.sleep(args.wait)

    if not any(proc.pid == pid for proc in dev.enumerate_processes()):
        print(f"[-] process {pid} died during startup — not attaching")
        sys.exit(2)

    print(f"[+] attaching")
    session = dev.attach(pid)
    print(f"    session={session}")

    if args.script:
        with open(args.script) as f:
            src = f.read()
        script = session.create_script(src)
        script.on("message", lambda m, d: print("[js]", m.get("payload", m)))
        script.load()
        print(f"[+] loaded {args.script}")

    print("[+] Press Ctrl-C to detach.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
