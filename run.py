"""Start AdLeak Detector on http://127.0.0.1:8765/ (local only)."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import webbrowser
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Keep the browser download inside the project unless the user chose another place.
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / ".browsers"))

from adleak.config import load_settings  # noqa: E402
from adleak.server import App, make_server  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="AdLeak Detector (local beta)")
    parser.add_argument("--port", type=int, help="port to listen on (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="don't open the web browser")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    if args.port:
        settings = replace(settings, port=args.port)
    app = App(settings)
    try:
        server = make_server(app)
    except OSError as exc:
        print(f"Could not start on port {settings.port}: {exc}. Is AdLeak already running? Try: python run.py --port 8766")
        return 1
    url = f"http://127.0.0.1:{app.port}/"
    print(f"\n  AdLeak Detector is running at {url}\n  Local only. Press Ctrl+C to stop.\n")
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
