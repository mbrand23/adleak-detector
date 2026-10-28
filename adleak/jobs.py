"""Scan queue with a fixed number of worker threads (the concurrency limit)."""

from __future__ import annotations

import logging
import queue
import threading
import time
import traceback

from .security import UnsafeUrlError
from .storage import ReportStore

log = logging.getLogger("adleak.jobs")


class QueueFull(Exception):
    pass


class ScanQueue:
    def __init__(self, store: ReportStore, scanner_factory, workers: int = 2, max_queued: int = 6):
        self.store = store
        self.scanner_factory = scanner_factory
        self.max_queued = max_queued
        self._queue: queue.Queue = queue.Queue()
        self._pending = 0
        self._lock = threading.Lock()
        self._threads = [threading.Thread(target=self._worker, name=f"scan-worker-{i}", daemon=True) for i in range(workers)]
        for t in self._threads:
            t.start()

    def pending(self) -> int:
        with self._lock:
            return self._pending

    def submit(self, scan_id: str, url: str, options: dict) -> None:
        with self._lock:
            if self._pending >= self.max_queued:
                raise QueueFull(f"{self._pending} scans are already waiting or running. Wait for one to finish.")
            self._pending += 1
        self._queue.put((scan_id, url, options))

    def _worker(self) -> None:
        while True:
            scan_id, url, options = self._queue.get()
            try:
                self._run(scan_id, url, options)
            finally:
                with self._lock:
                    self._pending -= 1
                self._queue.task_done()

    def _run(self, scan_id: str, url: str, options: dict) -> None:
        self.store.update(scan_id, state="scanning", started_at=time.time())
        self.store.append_progress(scan_id, "Scan started")
        try:
            scanner = self.scanner_factory()
            report = scanner.scan(url, scan_id, options, progress=lambda m: self.store.append_progress(scan_id, m))
            state = report.get("outcome", "completed")
            self.store.update(scan_id, state=state, report=report, completed_at=time.time())
            self.store.append_progress(scan_id, "Scan finished" if state == "completed" else "Scan finished, but the page could not be fully assessed")
        except UnsafeUrlError as exc:
            self.store.update(scan_id, state="failed", error=exc.message, completed_at=time.time())
        except Exception as exc:  # report the failure instead of losing the scan
            log.error("scan %s failed: %s", scan_id, traceback.format_exc())
            self.store.update(scan_id, state="failed", completed_at=time.time(),
                              error=f"The scanner hit an internal error: {type(exc).__name__}: {str(exc)[:300]}")
        finally:
            try:
                self.store.enforce_retention()
            except OSError:
                log.warning("retention cleanup failed", exc_info=True)
