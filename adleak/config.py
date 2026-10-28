"""Runtime settings. Values can be overridden with environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = PROJECT_ROOT / "web"


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class ScanLimits:
    navigation_timeout_ms: int = 30_000     # time allowed for the first response + DOMContentLoaded
    load_wait_ms: int = 10_000              # extra wait for the window "load" event
    settle_ms: int = 4_000                  # quiet period to let tags fire after load
    scan_deadline_s: int = 180              # hard ceiling for one scan
    max_links: int = 40                     # HTTP links tested per scan
    link_timeout_s: float = 10.0
    link_workers: int = 6
    max_link_redirects: int = 5
    max_bytes: int = 80 * 1024 * 1024       # total network budget per scan
    screenshot_max_height: int = 5_000      # full-page screenshots are cropped to this height
    retry_failed_navigation: bool = True


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765
    data_dir: Path = PROJECT_ROOT / "data"
    max_concurrent_scans: int = 2
    max_queued_scans: int = 6
    max_stored_reports: int = 200


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("ADLEAK_DATA_DIR", PROJECT_ROOT / "data"))
    return Settings(
        port=_int_env("ADLEAK_PORT", 8765),
        data_dir=data_dir,
        max_concurrent_scans=max(1, min(4, _int_env("ADLEAK_CONCURRENCY", 2))),
    )
