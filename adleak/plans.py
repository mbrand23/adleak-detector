"""Usage plans and fair-use limits.

Only the free beta plan is active. Paid plans are listed so limits are looked
up by plan rather than hard-coded; no billing exists and none is collected.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    key: str
    name: str
    scans_per_hour: int
    scans_per_day: int
    max_links: int
    monitoring: bool = False
    active: bool = True


FREE_BETA = Plan("free_beta", "Free beta", scans_per_hour=20, scans_per_day=100, max_links=40)

# Placeholders for "free to scan, pay to monitor". Not active, not purchasable.
FUTURE_PLANS = (
    Plan("monitor", "Monitor", 60, 500, 80, monitoring=True, active=False),
    Plan("agency", "Agency", 200, 2000, 120, monitoring=True, active=False),
)


class FairUse:
    """Sliding-window scan limits for the local workspace."""

    def __init__(self, plan: Plan = FREE_BETA, clock=time.time):
        self.plan = plan
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def seed(self, timestamps) -> None:
        cutoff = self._clock() - 86_400
        with self._lock:
            self._events = deque(sorted(t for t in timestamps if t >= cutoff))

    def _prune(self, now: float) -> None:
        while self._events and self._events[0] < now - 86_400:
            self._events.popleft()

    def status(self) -> dict:
        now = self._clock()
        with self._lock:
            self._prune(now)
            last_hour = sum(1 for t in self._events if t >= now - 3600)
            return {
                "plan": self.plan.name,
                "scans_last_hour": last_hour,
                "scans_last_day": len(self._events),
                "limit_per_hour": self.plan.scans_per_hour,
                "limit_per_day": self.plan.scans_per_day,
            }

    def try_consume(self) -> tuple[bool, str]:
        now = self._clock()
        with self._lock:
            self._prune(now)
            last_hour = sum(1 for t in self._events if t >= now - 3600)
            if last_hour >= self.plan.scans_per_hour:
                return False, f"Fair-use limit reached: {self.plan.scans_per_hour} scans per hour on the free beta. Try again later."
            if len(self._events) >= self.plan.scans_per_day:
                return False, f"Fair-use limit reached: {self.plan.scans_per_day} scans per day on the free beta."
            self._events.append(now)
            return True, ""
