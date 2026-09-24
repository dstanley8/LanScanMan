"""
The sequencing rules for running a schedule list, independent of how each
transfer is executed. ScheduledRunner (workers/scheduled_runner.py) plugs in
RsyncWorker; tests plug in a fake.

Overall status: completed — every transfer succeeded
                partial   — something failed/was rejected, list continued
                aborted   — stop requested, or a failure with on_transfer_failure="abort"
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable

from lanscanman.core.schedules import RunLogEntry, Schedule, Transfer
from lanscanman.log import log

# (transfer) -> (final_status, total_bytes); status as RsyncWorker reports it
RunTransfer = Callable[[Transfer], tuple[str, int]]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def is_failure(status: str) -> bool:
    return status.startswith("Failed") or status in ("Cancelled", "Interrupted")


def run_schedule(sched: Schedule,
                 run_transfer: RunTransfer,
                 should_stop: Callable[[], bool] = lambda: False,
                 on_started: Callable[[int, Transfer], None] = lambda i, t: None,
                 on_finished: Callable[[int, str, int], None] = lambda i, s, b: None,
                 ) -> RunLogEntry:
    started = _now()
    results: list[dict] = []
    overall = "completed"

    for idx, t in enumerate(sched.transfers):
        if should_stop():
            overall = "aborted"
            break

        # Re-validate as a last line of defence against a tampered file
        ok, reason = t.validate()
        if not ok:
            log.error(f"schedule {sched.name!r} transfer {idx} rejected: {reason}")
            results.append({"source": t.full_source, "dest": t.full_dest,
                            "status": "rejected", "bytes": 0, "reason": reason})
            if sched.on_transfer_failure == "abort":
                overall = "aborted"
                break
            overall = "partial"
            continue

        on_started(idx, t)
        try:
            status, total_bytes = run_transfer(t)
        except Exception as e:
            log.exception(f"scheduled rsync failed: {e}")
            status, total_bytes = "Failed", 0

        results.append({"source": t.full_source, "dest": t.full_dest,
                        "status": status, "bytes": total_bytes})
        on_finished(idx, status, total_bytes)

        if is_failure(status):
            if sched.on_transfer_failure == "abort":
                overall = "aborted"
                break
            overall = "partial"

        if should_stop():
            overall = "aborted"
            break

    return RunLogEntry(started=started, finished=_now(),
                       status=overall, transfers=results)
