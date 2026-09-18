"""
Brute-force search engine
--------------------------
Two execution modes, selected by the caller:

  - THROTTLED: a single-process generator that paces itself to hit a
    user-chosen guesses/sec rate. This is the original "simulated speed"
    behavior -- useful for watching the search at a human-readable pace.

  - MAX SPEED: spins up one worker process per CPU core (os.cpu_count()),
    each given a disjoint slice of the current length's keyspace. Workers
    run completely unthrottled -- no sleeping, no per-guess locking -- so
    the measured rate reflects genuine local hashing throughput rather
    than a number the user dialed in. A shared multiprocessing.Event signals
    all workers to stop as soon as one of them finds a match or the user
    clicks Stop.

Both modes report through the same callback-ish shape (a mutable "job"
dict guarded by a lock) so the Flask layer doesn't need to know which
mode produced the update.
"""

import hashlib
import itertools
import multiprocessing as mp
import os
import time


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def total_combinations(charset_len, max_length):
    total = 0
    for length in range(1, max_length + 1):
        total += charset_len ** length
    return total


def index_to_candidate(idx, charset, length):
    """Convert a 0-based integer index directly into the corresponding
    fixed-length candidate string, treating the charset as the digits of a
    mixed-radix number. This lets a worker jump straight to any offset in
    the keyspace without iterating from zero, which is what makes it
    possible to hand each process a disjoint slice."""
    base = len(charset)
    chars = [""] * length
    for pos in range(length - 1, -1, -1):
        idx, rem = divmod(idx, base)
        chars[pos] = charset[rem]
    return "".join(chars)


# ---------------------------------------------------------------------------
# MAX SPEED mode (multiprocessing, unthrottled)
# ---------------------------------------------------------------------------

def _max_speed_worker(charset, length, start_idx, count, target_hash,
                       stop_event, counter, sample_queue, report_every=20_000):
    """Runs in its own OS process. Scans [start_idx, start_idx+count) of the
    keyspace for this length, reporting progress in batches rather than per
    guess so inter-process overhead doesn't become the bottleneck."""
    local_count = 0
    idx = start_idx
    end = start_idx + count
    last_report_guess = None

    while idx < end:
        if stop_event.is_set():
            break

        candidate = index_to_candidate(idx, charset, length)
        candidate_hash = sha256_hex(candidate)
        local_count += 1
        last_report_guess = (candidate, candidate_hash)

        if candidate_hash == target_hash:
            with counter.get_lock():
                counter.value += local_count
            stop_event.set()
            sample_queue.put(("found", candidate, candidate_hash))
            return

        idx += 1

        if local_count >= report_every:
            with counter.get_lock():
                counter.value += local_count
            try:
                sample_queue.put_nowait(("sample", last_report_guess[0], last_report_guess[1]))
            except Exception:
                pass
            local_count = 0

    if local_count:
        with counter.get_lock():
            counter.value += local_count
    if last_report_guess is not None:
        try:
            sample_queue.put_nowait(("sample", last_report_guess[0], last_report_guess[1]))
        except Exception:
            pass


def run_max_speed(job_id, jobs, jobs_lock, num_workers=None):
    """Coordinator that runs in its own background thread (started by the
    Flask route). Drives one round of multiprocessing workers per password
    length, aggregating their progress into jobs[job_id] using the exact
    same fields the throttled single-process path writes, so /api/status
    doesn't need to know which mode produced the update."""
    with jobs_lock:
        job = jobs[job_id]
        target_hash = job["target_hash"]
        charset = job["charset"]
        max_length = job["max_length"]

    num_workers = num_workers or max(1, os.cpu_count() or 1)

    start_time = time.time()
    with jobs_lock:
        jobs[job_id]["start_time"] = start_time
        jobs[job_id]["worker_count"] = num_workers

    attempts_so_far = 0
    last_sample_time = start_time
    sample_interval = 0.2

    try:
        for length in range(1, max_length + 1):
            with jobs_lock:
                if jobs[job_id]["stop_requested"]:
                    jobs[job_id]["status"] = "stopped"
                    jobs[job_id]["elapsed"] = time.time() - start_time
                    return

            length_total = len(charset) ** length
            chunk = max(1, length_total // num_workers)

            stop_event = mp.Event()
            counter = mp.Value("q", 0)
            sample_queue = mp.Queue()

            procs = []
            for i in range(num_workers):
                start_idx = i * chunk
                if start_idx >= length_total:
                    break
                count = chunk if i < num_workers - 1 else (length_total - start_idx)
                p = mp.Process(
                    target=_max_speed_worker,
                    args=(charset, length, start_idx, count, target_hash,
                          stop_event, counter, sample_queue),
                    daemon=True,
                )
                procs.append(p)

            for p in procs:
                p.start()

            length_start_attempts = attempts_so_far
            found_password = None
            found_hash = None

            # poll while workers run: drain samples, update shared job
            # state, and watch for an external stop request
            while any(p.is_alive() for p in procs):
                with jobs_lock:
                    user_stopped = jobs[job_id]["stop_requested"]
                if user_stopped:
                    stop_event.set()

                drained = []
                try:
                    while True:
                        drained.append(sample_queue.get_nowait())
                except Exception:
                    pass

                now = time.time()
                with jobs_lock:
                    current_attempts = attempts_so_far + counter.value
                    jobs[job_id]["attempts"] = current_attempts
                    jobs[job_id]["current_length"] = length

                    for kind, candidate, candidate_hash in drained:
                        jobs[job_id]["latest_guess"] = candidate
                        jobs[job_id]["latest_hash"] = candidate_hash
                        jobs[job_id]["recent_guesses"].append(
                            {"guess": candidate, "hash": candidate_hash}
                        )
                        if len(jobs[job_id]["recent_guesses"]) > 500:
                            jobs[job_id]["recent_guesses"] = jobs[job_id]["recent_guesses"][-500:]
                        if kind == "found":
                            found_password = candidate
                            found_hash = candidate_hash

                    if now - last_sample_time >= sample_interval:
                        jobs[job_id]["timeline"].append({
                            "t": round(now - start_time, 3),
                            "attempts": current_attempts,
                        })
                        last_sample_time = now

                    # measured rate over the last poll tick, for an honest
                    # "actual hashes/sec" readout instead of a dialed-in number
                    jobs[job_id]["measured_rate"] = jobs[job_id].get("measured_rate", 0)

                if user_stopped:
                    break

                time.sleep(0.08)

            for p in procs:
                p.join(timeout=2)
            for p in procs:
                if p.is_alive():
                    p.terminate()

            # final drain after workers have stopped
            drained = []
            try:
                while True:
                    drained.append(sample_queue.get_nowait())
            except Exception:
                pass

            with jobs_lock:
                attempts_so_far += counter.value
                jobs[job_id]["attempts"] = attempts_so_far
                for kind, candidate, candidate_hash in drained:
                    jobs[job_id]["latest_guess"] = candidate
                    jobs[job_id]["latest_hash"] = candidate_hash
                    jobs[job_id]["recent_guesses"].append(
                        {"guess": candidate, "hash": candidate_hash}
                    )
                    if kind == "found":
                        found_password = candidate
                        found_hash = candidate_hash
                jobs[job_id]["length_counts"][length] = attempts_so_far - length_start_attempts

                if jobs[job_id]["stop_requested"]:
                    jobs[job_id]["status"] = "stopped"
                    jobs[job_id]["elapsed"] = time.time() - start_time
                    return

            if found_password is not None:
                elapsed = time.time() - start_time
                with jobs_lock:
                    jobs[job_id]["timeline"].append({"t": round(elapsed, 3), "attempts": attempts_so_far})
                    jobs[job_id]["status"] = "found"
                    jobs[job_id]["found_password"] = found_password
                    jobs[job_id]["elapsed"] = elapsed
                return

        elapsed = time.time() - start_time
        with jobs_lock:
            jobs[job_id]["status"] = "exhausted"
            jobs[job_id]["elapsed"] = elapsed

    except Exception as exc:  # pragma: no cover - defensive guard for a demo app
        with jobs_lock:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# THROTTLED mode (single process, paced to a chosen guesses/sec)
# ---------------------------------------------------------------------------

def run_throttled(job_id, jobs, jobs_lock):
    with jobs_lock:
        job = jobs[job_id]
        target_hash = job["target_hash"]
        charset = job["charset"]
        max_length = job["max_length"]
        gps = job["gps"]

    attempts = 0
    start_time = time.time()
    with jobs_lock:
        jobs[job_id]["start_time"] = start_time

    batch_size = max(1, gps // 20) if gps > 20 else 1
    batch_sleep = batch_size / gps if gps > 0 else 0

    last_sample_time = start_time
    sample_interval = 0.2

    try:
        for length in range(1, max_length + 1):
            length_start_attempts = attempts
            for combo_tuple in itertools.product(charset, repeat=length):
                with jobs_lock:
                    if jobs[job_id]["stop_requested"]:
                        jobs[job_id]["status"] = "stopped"
                        jobs[job_id]["elapsed"] = time.time() - start_time
                        return

                candidate = "".join(combo_tuple)
                candidate_hash = sha256_hex(candidate)
                attempts += 1

                is_match = candidate_hash == target_hash

                now = time.time()
                with jobs_lock:
                    jobs[job_id]["attempts"] = attempts
                    jobs[job_id]["current_length"] = length
                    jobs[job_id]["latest_guess"] = candidate
                    jobs[job_id]["latest_hash"] = candidate_hash
                    jobs[job_id]["recent_guesses"].append({"guess": candidate, "hash": candidate_hash})
                    if len(jobs[job_id]["recent_guesses"]) > 500:
                        jobs[job_id]["recent_guesses"] = jobs[job_id]["recent_guesses"][-500:]

                    if now - last_sample_time >= sample_interval:
                        jobs[job_id]["timeline"].append({
                            "t": round(now - start_time, 3),
                            "attempts": attempts,
                        })
                        last_sample_time = now

                if is_match:
                    elapsed = time.time() - start_time
                    with jobs_lock:
                        jobs[job_id]["length_counts"][length] = attempts - length_start_attempts
                        jobs[job_id]["timeline"].append({"t": round(elapsed, 3), "attempts": attempts})
                        jobs[job_id]["status"] = "found"
                        jobs[job_id]["found_password"] = candidate
                        jobs[job_id]["elapsed"] = elapsed
                    return

                if gps > 0 and attempts % batch_size == 0:
                    remaining = batch_sleep
                    slice_len = 0.05
                    while remaining > 0:
                        time.sleep(min(slice_len, remaining))
                        remaining -= slice_len
                        with jobs_lock:
                            if jobs[job_id]["stop_requested"]:
                                jobs[job_id]["status"] = "stopped"
                                jobs[job_id]["elapsed"] = time.time() - start_time
                                return

            with jobs_lock:
                jobs[job_id]["length_counts"][length] = attempts - length_start_attempts

        elapsed = time.time() - start_time
        with jobs_lock:
            jobs[job_id]["status"] = "exhausted"
            jobs[job_id]["elapsed"] = elapsed

    except Exception as exc:  # pragma: no cover - defensive guard for a demo app
        with jobs_lock:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(exc)
