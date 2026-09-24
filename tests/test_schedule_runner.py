from lanscanman.core.schedule_runner import is_failure, run_schedule
from lanscanman.core.schedules import Schedule, Transfer


def _t(name):
    return Transfer(full_source=f"/src/{name}", full_dest=f"/dst/{name}",
                    src_path=f"/src/{name}", dst_path=f"/dst/{name}", args=["-a"])


class FakeRsync:
    """Returns scripted statuses and records which transfers ran."""
    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.ran = []

    def __call__(self, t):
        self.ran.append(t.full_source)
        status = self.statuses.pop(0)
        if isinstance(status, Exception):
            raise status
        return status, 100 if status == "Completed" else 0


def test_is_failure():
    assert is_failure("Failed")
    assert is_failure("Failed: timeout")
    assert is_failure("Cancelled")
    assert not is_failure("Completed")


def test_all_succeed():
    sched = Schedule(transfers=[_t("a"), _t("b")])
    events = []
    entry = run_schedule(sched, FakeRsync("Completed", "Completed"),
                         on_started=lambda i, t: events.append(("start", i)),
                         on_finished=lambda i, s, b: events.append(("done", i, s, b)))
    assert entry.status == "completed"
    assert [r["bytes"] for r in entry.transfers] == [100, 100]
    assert events == [("start", 0), ("done", 0, "Completed", 100),
                      ("start", 1), ("done", 1, "Completed", 100)]
    assert entry.started and entry.finished


def test_failure_with_continue_is_partial():
    rsync = FakeRsync("Failed", "Completed")
    entry = run_schedule(Schedule(transfers=[_t("a"), _t("b")]), rsync)
    assert entry.status == "partial"
    assert rsync.ran == ["/src/a", "/src/b"]


def test_failure_with_abort_stops():
    rsync = FakeRsync("Failed", "Completed")
    sched = Schedule(transfers=[_t("a"), _t("b")], on_transfer_failure="abort")
    entry = run_schedule(sched, rsync)
    assert entry.status == "aborted"
    assert rsync.ran == ["/src/a"]


def test_exception_counts_as_failure():
    entry = run_schedule(Schedule(transfers=[_t("a")]), FakeRsync(RuntimeError("boom")))
    assert entry.status == "partial"
    assert entry.transfers[0]["status"] == "Failed"


def test_tampered_transfer_is_rejected_without_running():
    rsync = FakeRsync("Completed")
    bad = _t("a")
    bad.full_dest = "/dst;rm -rf ~"
    entry = run_schedule(Schedule(transfers=[bad, _t("b")]), rsync)
    assert entry.transfers[0]["status"] == "rejected"
    assert rsync.ran == ["/src/b"]
    assert entry.status == "partial"


def test_stop_request_aborts_between_transfers():
    rsync = FakeRsync("Completed", "Completed")
    stop = iter([False, True])
    entry = run_schedule(Schedule(transfers=[_t("a"), _t("b")]), rsync,
                         should_stop=lambda: next(stop, True))
    assert entry.status == "aborted"
    assert rsync.ran == ["/src/a"]
