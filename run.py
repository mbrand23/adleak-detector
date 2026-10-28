"""Start AdLeak Detector on http://127.0.0.1:8765/ (local only).

With --tailscale, your own devices on your private Tailscale network can also
open it, through `tailscale serve` (see PHONE_ACCESS.md). The server itself
still listens on 127.0.0.1 only.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Keep the browser download inside the project unless the user chose another place.
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / ".browsers"))

from adleak.config import load_settings, parse_hostname  # noqa: E402
from adleak.server import App, make_server  # noqa: E402

TAILSCALE_DEFAULT = r"C:\Program Files\Tailscale\tailscale.exe"


def tailscale_exe() -> str | None:
    found = shutil.which("tailscale")
    if found:
        return found
    return TAILSCALE_DEFAULT if os.path.isfile(TAILSCALE_DEFAULT) else None


def tailscale_name() -> str:
    """Return this computer's private Tailscale DNS name, or raise with a plain explanation."""
    exe = tailscale_exe()
    if not exe:
        raise RuntimeError("Tailscale is not installed. Install it from https://tailscale.com/download/windows and sign in.")
    try:
        out = subprocess.run([exe, "status", "--json"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not run Tailscale: {exc}")
    try:
        status = json.loads(out.stdout or "{}")
    except json.JSONDecodeError:
        status = {}
    if status.get("BackendState") != "Running":
        raise RuntimeError("Tailscale is installed but not connected. Open Tailscale from the system tray and sign in.")
    name = (status.get("Self") or {}).get("DNSName", "")
    if not name:
        raise RuntimeError("Tailscale did not report a name for this computer. Turn on MagicDNS in the Tailscale admin console.")
    return parse_hostname(name)


def main() -> int:
    parser = argparse.ArgumentParser(description="AdLeak Detector (local beta)")
    parser.add_argument("--port", type=int, help="port to listen on (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="don't open the web browser")
    parser.add_argument("--tailscale", action="store_true",
                        help="also accept requests from your private Tailscale network via 'tailscale serve'")
    parser.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                        help="extra hostname the app may be reached by (advanced; normally use --tailscale)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    if args.port:
        settings = replace(settings, port=args.port)
    extra = list(settings.extra_hosts)
    try:
        extra += [parse_hostname(h) for h in args.allow_host]
        if args.tailscale:
            extra.append(tailscale_name())
    except (ValueError, RuntimeError) as exc:
        print(f"\n  {exc}\n")
        return 1
    settings = replace(settings, extra_hosts=tuple(dict.fromkeys(extra)))

    app = App(settings)
    try:
        server = make_server(app)
    except OSError as exc:
        print(f"Could not start on port {settings.port}: {exc}. Is AdLeak already running? Try: python run.py --port 8766")
        return 1
    url = f"http://127.0.0.1:{app.port}/"
    print(f"\n  AdLeak Detector is running at {url}")
    if settings.extra_hosts:
        for name in settings.extra_hosts:
            print(f"  On your other Tailscale devices: https://{name}/")
        print(f"  (Needs 'tailscale serve --bg {app.port}' to be set up once; see PHONE_ACCESS.md.)")
        print("  Never use 'tailscale funnel' with AdLeak: that would put it on the public internet.")
    else:
        print("  Local only.")
    print("  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AdLeak Detector.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
