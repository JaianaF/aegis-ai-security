from __future__ import annotations

import asyncio
import signal

from .config import WORKER_POLL_SECONDS
from .db import init_db
from .queue import claim_next_scan, execute_scan_job, requeue_stale_scans


async def run_worker() -> None:
    init_db()
    requeue_stale_scans()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    print("AegisAI worker v0.3 started", flush=True)
    while not stop.is_set():
        scan_id = claim_next_scan()
        if scan_id is None:
            try:
                await asyncio.wait_for(stop.wait(), timeout=WORKER_POLL_SECONDS)
            except asyncio.TimeoutError:
                pass
            continue
        await execute_scan_job(scan_id)


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
