"""Test plan item 11: report saving and retrieval."""

import time

from adleak.plans import FairUse, Plan
from adleak.storage import ReportStore, new_scan_id, valid_id


def test_save_load_list_delete(tmp_path):
    store = ReportStore(tmp_path)
    sid = new_scan_id()
    store.save({"id": sid, "submitted_url": "https://a.com/", "state": "completed", "created_at": time.time(),
                "report": {"summary": {"FAILED": 1}, "final_url": "https://a.com/x"}})
    assert store.load(sid)["submitted_url"] == "https://a.com/"
    listed = store.list()
    assert listed[0]["id"] == sid and listed[0]["summary"] == {"FAILED": 1}
    (store.shots_dir / sid).mkdir()
    (store.shots_dir / sid / "desktop.png").write_bytes(b"png")
    assert store.screenshot_path(sid, "desktop.png")
    assert store.delete(sid)
    assert store.load(sid) is None
    assert not (store.shots_dir / sid).exists()


def test_rejects_path_traversal_ids_and_names(tmp_path):
    store = ReportStore(tmp_path)
    for bad in ("../../etc/passwd", "..", "", "A" * 32, "0" * 31, None):
        assert not valid_id(bad)
        assert store.load(bad) is None
        assert store.delete(bad) is False
    sid = new_scan_id()
    assert store.screenshot_path(sid, "../scans/x.json") is None
    assert store.screenshot_path(sid, "other.png") is None


def test_progress_and_corrupt_file(tmp_path):
    store = ReportStore(tmp_path)
    sid = new_scan_id()
    store.save({"id": sid, "state": "scanning", "created_at": 1})
    for i in range(70):
        store.append_progress(sid, f"step {i}")
    assert len(store.load(sid)["progress"]) == 60
    (store.scans_dir / f"{sid}.json").write_text("{not json", encoding="utf-8")
    assert store.load(sid)["state"] == "failed"


def test_retention_and_restart_recovery(tmp_path):
    store = ReportStore(tmp_path, max_reports=3)
    ids = []
    for i in range(5):
        sid = new_scan_id()
        ids.append(sid)
        store.save({"id": sid, "state": "completed", "created_at": 100 + i})
    running = new_scan_id()
    store.save({"id": running, "state": "scanning", "created_at": 1})
    assert store.enforce_retention() == 2
    assert store.load(ids[0]) is None and store.load(ids[4]) is not None
    assert store.load(running) is not None
    assert store.recover_interrupted() == 1
    assert store.load(running)["state"] == "failed"


def test_fair_use_limits():
    now = [1000.0]
    fu = FairUse(Plan("t", "Test", scans_per_hour=2, scans_per_day=3, max_links=5), clock=lambda: now[0])
    assert fu.try_consume()[0] and fu.try_consume()[0]
    ok, msg = fu.try_consume()
    assert not ok and "per hour" in msg
    now[0] += 3601
    assert fu.try_consume()[0]
    ok, msg = fu.try_consume()
    assert not ok and "per day" in msg
