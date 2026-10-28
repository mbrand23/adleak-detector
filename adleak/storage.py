"""Local JSON report storage.

Each scan is one file: data/scans/<id>.json, written atomically. Screenshots
live in data/screenshots/<id>/. IDs are random hex strings and are validated
before they touch the filesystem. Every record carries a ``workspace`` field
("local" for now) so per-account separation can be added later without
reshaping the data.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import uuid
from pathlib import Path

ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SCREENSHOT_NAMES = frozenset({"desktop.png", "desktop-full.png", "mobile.png", "mobile-full.png"})
ACTIVE_STATES = ("queued", "scanning")


def new_scan_id() -> str:
    return uuid.uuid4().hex


def valid_id(scan_id: object) -> bool:
    return isinstance(scan_id, str) and bool(ID_PATTERN.match(scan_id))


class ReportStore:
    def __init__(self, data_dir: Path, max_reports: int = 200):
        self.root = Path(data_dir)
        self.scans_dir = self.root / "scans"
        self.shots_dir = self.root / "screenshots"
        self.max_reports = max_reports
        self._lock = threading.RLock()
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.shots_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, scan_id: str) -> Path:
        if not valid_id(scan_id):
            raise ValueError("invalid scan id")
        return self.scans_dir / f"{scan_id}.json"

    def save(self, record: dict) -> None:
        path = self._path(record["id"])
        tmp = path.with_suffix(f".{uuid.uuid4().hex[:8]}.tmp")
        with self._lock:
            tmp.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
            for attempt in range(5):
                try:
                    os.replace(tmp, path)
                    break
                except PermissionError:
                    # Windows can briefly lock a file another thread is reading.
                    if attempt == 4:
                        raise
                    time.sleep(0.05 * (attempt + 1))

    def load(self, scan_id: str) -> dict | None:
        if not valid_id(scan_id):
            return None
        path = self._path(scan_id)
        with self._lock:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                return None
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {"id": scan_id, "state": "failed", "error": "This report file is damaged and could not be read.",
                        "submitted_url": "", "created_at": 0}

    def update(self, scan_id: str, **fields) -> dict | None:
        with self._lock:
            record = self.load(scan_id)
            if record is None:
                return None
            record.update(fields)
            self.save(record)
            return record

    def append_progress(self, scan_id: str, message: str) -> None:
        with self._lock:
            record = self.load(scan_id)
            if record is None:
                return
            record.setdefault("progress", []).append({"at": time.time(), "message": message[:300]})
            record["progress"] = record["progress"][-60:]
            self.save(record)

    def list(self, limit: int = 100) -> list[dict]:
        items = []
        with self._lock:
            for path in self.scans_dir.glob("*.json"):
                try:
                    record = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                    continue
                items.append({
                    "id": record.get("id"), "submitted_url": record.get("submitted_url"),
                    "final_url": (record.get("report") or {}).get("final_url"),
                    "state": record.get("state"), "created_at": record.get("created_at"),
                    "completed_at": record.get("completed_at"),
                    "summary": (record.get("report") or {}).get("summary"),
                })
        items.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
        return items[:limit]

    def delete(self, scan_id: str) -> bool:
        if not valid_id(scan_id):
            return False
        with self._lock:
            path = self._path(scan_id)
            existed = path.exists()
            if existed:
                path.unlink()
            shutil.rmtree(self.shots_dir / scan_id, ignore_errors=True)
            return existed

    def screenshot_path(self, scan_id: str, name: str) -> Path | None:
        if not valid_id(scan_id) or name not in SCREENSHOT_NAMES:
            return None
        path = self.shots_dir / scan_id / name
        return path if path.is_file() else None

    def enforce_retention(self) -> int:
        """Delete the oldest finished reports beyond ``max_reports``."""
        items = [r for r in self.list(limit=100_000) if r.get("state") not in ACTIVE_STATES]
        removed = 0
        for record in items[self.max_reports:]:
            if self.delete(record["id"]):
                removed += 1
        return removed

    def recover_interrupted(self) -> int:
        """Mark scans that were running when the app stopped as failed."""
        count = 0
        for item in self.list(limit=100_000):
            if item.get("state") in ACTIVE_STATES:
                self.update(item["id"], state="failed", completed_at=time.time(),
                            error="The scan was interrupted because AdLeak Detector was closed or restarted.")
                count += 1
        return count
