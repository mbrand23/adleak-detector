"""The finding record every check produces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

PASSED = "PASSED"
FAILED = "FAILED"
WARNING = "WARNING"
INCONCLUSIVE = "INCONCLUSIVE"
STATUSES = (FAILED, WARNING, INCONCLUSIVE, PASSED)

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"

CATEGORIES = {
    "access": "Website accessibility",
    "links": "Links",
    "sales": "Sales actions",
    "tracking": "Advertising tracking",
    "campaign": "Ad campaign URL",
    "mobile": "Mobile and layout",
    "resources": "Page resources",
    "safety": "Scanner safety",
}


@dataclass
class Finding:
    category: str
    title: str
    status: str
    severity: str
    explanation: str
    recommendation: str = ""
    evidence: list[str] = field(default_factory=list)
    device: str = "all"
    check: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evidence"] = [str(item)[:600] for item in self.evidence[:25]]
        return data


def summarise(findings: list[dict]) -> dict:
    counts = {status: 0 for status in STATUSES}
    for item in findings:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return counts
