"""
Brute Force Attack Simulator
-----------------------------
An educational cybersecurity demo that simulates how a brute-force
password attack works against a SHA-256 hash. The user supplies their
own username/password (this is a self-demo, not a tool for attacking
unknown targets) and either a simulated guesses-per-second rate or "MAX
speed" mode, which runs unthrottled across all available CPU cores via
multiprocessing and reports the genuinely measured hash rate rather than
a number the user dialed in. There is no character-set picker -- the
simulator always searches the full combined alphabet (lower + upper +
digits + symbols), which is what makes the demo honest about how brutal
a real attacker's search space is. The search length is derived
automatically from the password's own length (1-10 characters allowed).
Short passwords crack almost instantly even over the full alphabet;
passwords toward the 8-10 character end push the search space into the
quadrillions-to-quintillions, so the UI shows an estimated-time warning
before launch but still lets the user start the run if they want to
watch it work for as long as they like. The backend generates candidates
in increasing length order, hashes each one, and runs in a background
thread (or, in MAX speed mode, a pool of worker processes coordinated by
a background thread) while the browser polls /api/status for live
progress. On a successful crack, per-length attempt counts and a
timestamped attempts log are returned so the frontend can render charts
of how the search progressed.
"""

import os
import string
import threading
import time
import uuid
from threading import Lock

from flask import Flask, jsonify, render_template, request

import bruteforce_engine as engine

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration / safety limits
# ---------------------------------------------------------------------------
MIN_ALLOWED_LENGTH = 1            # password length range -- 1 up to 10. Even a
MAX_ALLOWED_LENGTH = 10          # 1-character password still searches the full
                                  # combined charset, so short passwords crack
                                  # almost instantly while 10-char ones stay
                                  # genuinely huge -- that contrast is the point.

# The throttled slider tops out at a realistic single-process Python rate.
# There's a separate "MAX speed" mode (selected with gps == MAX_SPEED_SENTINEL)
# that ignores this entirely and runs unthrottled across every CPU core via
# multiprocessing -- see bruteforce_engine.run_max_speed.
MAX_GUESSES_PER_SECOND = 1_000_000
MIN_GUESSES_PER_SECOND = 1
MAX_SPEED_SENTINEL = -1
CPU_COUNT = max(1, os.cpu_count() or 1)

# There's no charset picker in this version -- every run searches the full
# combined alphabet below. This is what a real brute-force attacker who
# doesn't know anything about the password's composition would have to do,
# so it's the more honest default for a security-education demo.
FULL_CHARSET = (
    string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+"
)

# NOTE: there is intentionally no MAX_SEARCH_SPACE rejection in this version.
# At the upper end of the length range (8-10 characters) over the full
# ~76-character alphabet, the true search space is quadrillions to
# quintillions of candidates (76^8 ≈ 1.1 quadrillion, 76^10 ≈ 6.3
# quintillion) -- no demo, and in practice no realistic attacker without
# serious distributed hardware, actually exhausts that. Rather than silently
# blocking the run, /api/start returns an "estimated_seconds" figure so the
# frontend can warn the user just how long the search would realistically
# take, while still letting them launch it if they want to. Shorter
# passwords (1-7 characters) stay well within reach and finish quickly.


CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+",
}  # kept only so index() can still show the four categories for context in
   # the page copy ("your password could start with any of these...");
   # the actual search always uses FULL_CHARSET, not a subset of these

# In-memory registry of running/finished simulation jobs, keyed by job id.
# Each job is a small dict describing its own state; a lock guards mutation
# since Flask's dev server can interleave requests across threads.
JOBS = {}
JOBS_LOCK = Lock()


def sha256_hex(text):
    return engine.sha256_hex(text)


def total_combinations(charset_len, max_length):
    return engine.total_combinations(charset_len, max_length)


def estimate_seconds(total_space, gps):
    """Worst-case seconds to exhaust total_space at the given guesses/sec.
    Not meaningful for MAX speed mode (the caller should skip this there
    since the real rate isn't known until the job is actually running)."""
    if gps <= 0:
        return float("inf")
    return total_space / gps


def run_job(job_id):
    """Dispatcher run in a background thread. Picks the throttled
    single-process engine or the unthrottled multiprocessing engine based
    on the job's gps value, then delegates entirely -- both engines write
    into JOBS using the same field names, so /api/status doesn't care
    which one produced the update."""
    with JOBS_LOCK:
        gps = JOBS[job_id]["gps"]

    if gps == MAX_SPEED_SENTINEL:
        engine.run_max_speed(job_id, JOBS, JOBS_LOCK, num_workers=CPU_COUNT)
    else:
        engine.run_throttled(job_id, JOBS, JOBS_LOCK)


@app.route("/")
def index():
    return render_template("index.html", min_allowed_length=MIN_ALLOWED_LENGTH,
                            max_allowed_length=MAX_ALLOWED_LENGTH,
                            charset_size=len(FULL_CHARSET),
                            min_gps=MIN_GUESSES_PER_SECOND, max_gps=MAX_GUESSES_PER_SECOND,
                            cpu_count=CPU_COUNT, max_speed_sentinel=MAX_SPEED_SENTINEL)


@app.route("/api/start", methods=["POST"])
def start_job():
    data = request.get_json(force=True)

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    gps = data.get("gps")

    if not password:
        return jsonify({"error": "Password is required."}), 400

    charset = FULL_CHARSET

    # Every character in the password must exist in the full charset for the
    # search to ever reach it. In practice this only fails for characters
    # outside ascii letters/digits/the symbol set above (e.g. accented
    # characters, emoji, non-Latin scripts).
    missing_chars = sorted(set(ch for ch in password if ch not in charset))
    if missing_chars:
        return jsonify({
            "error": f"Password contains characters outside the supported set: "
                      f"{''.join(missing_chars)}. Use letters, digits, or the symbols "
                      f"!@#$%^&*()-_=+ only."
        }), 400

    # Length is derived straight from the password the user typed in, clamped
    # to the allowed length range. The <input minlength/maxlength> in the HTML already
    # enforces this client-side, but never trust the client alone.
    max_length = len(password)
    if max_length < MIN_ALLOWED_LENGTH or max_length > MAX_ALLOWED_LENGTH:
        return jsonify({
            "error": f"Password must be between {MIN_ALLOWED_LENGTH} and {MAX_ALLOWED_LENGTH} "
                      f"characters long."
        }), 400

    try:
        gps = int(gps)
    except (TypeError, ValueError):
        return jsonify({"error": "Guesses per second must be a number."}), 400

    is_max_speed = (gps == MAX_SPEED_SENTINEL)
    if not is_max_speed:
        gps = max(MIN_GUESSES_PER_SECOND, min(MAX_GUESSES_PER_SECOND, gps))

    total_space = total_combinations(len(charset), max_length)
    # In MAX speed mode the real rate isn't known until workers are actually
    # running (it depends on this machine's CPU), so there's no honest
    # estimate to give yet -- the frontend shows the measured rate live
    # instead once the job starts, rather than a pre-computed guess.
    estimated_seconds = None if is_max_speed else estimate_seconds(total_space, gps)

    target_hash = sha256_hex(password)
    job_id = uuid.uuid4().hex

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",
            "username": username,
            "target_hash": target_hash,
            "charset": charset,
            "max_length": max_length,
            "gps": gps,
            "is_max_speed": is_max_speed,
            "worker_count": CPU_COUNT if is_max_speed else 1,
            "attempts": 0,
            "current_length": 1,
            "latest_guess": "",
            "latest_hash": "",
            "recent_guesses": [],
            "found_password": None,
            "elapsed": 0,
            "stop_requested": False,
            "total_space": total_space,
            "length_counts": {},   # length -> attempts tried at that length (bar chart)
            "timeline": [],         # [{t, attempts}, ...] sampled over time (line chart)
            "error": None,
            "start_time": time.time(),
        }

    # Run the brute-force loop in a background thread so /api/start returns
    # immediately and the frontend can begin polling /api/status. In MAX
    # speed mode this thread itself just coordinates a pool of worker
    # processes (see bruteforce_engine.run_max_speed) rather than hashing
    # anything itself.
    thread = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    thread.start()

    return jsonify({
        "job_id": job_id,
        "username": username,
        "target_hash": target_hash,
        "total_space": total_space,
        "charset_size": len(charset),
        "max_length": max_length,
        "is_max_speed": is_max_speed,
        "worker_count": CPU_COUNT if is_max_speed else 1,
        # Worst-case seconds to exhaust the full space at this gps. At the
        # upper end of the length range (8-10 chars over a 76-char alphabet) this is routinely quadrillions of
        # seconds -- the frontend uses this to show a realistic time warning
        # before the user launches, without blocking them from running anyway.
        # null in MAX speed mode since the real rate isn't known until the
        # job is actually running.
        "estimated_seconds": estimated_seconds,
    })


@app.route("/api/status/<job_id>")
def status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Unknown job id."}), 404

        # pop "new since last poll" guesses so payload stays small; client
        # appends them to its own running list for the live feed. Cap how
        # many we send in one poll so very high guesses/sec settings don't
        # produce a huge JSON payload -- the attempts counter stays exact
        # either way, only the ledger preview is sampled.
        all_new = job["recent_guesses"]
        job["recent_guesses"] = []
        MAX_PER_POLL = 100
        if len(all_new) > MAX_PER_POLL:
            new_guesses = all_new[-MAX_PER_POLL:]
        else:
            new_guesses = all_new

        elapsed_now = round(job["elapsed"], 3) if job["status"] in ("found", "stopped", "exhausted") else round(time.time() - job["start_time"], 3)
        # Genuine measured rate -- attempts actually completed divided by
        # elapsed wall-clock time. This is what makes MAX speed mode honest:
        # the number shown is derived from real work done, not a value the
        # user dialed in on a slider.
        measured_rate = (job["attempts"] / elapsed_now) if elapsed_now > 0 else 0

        payload = {
            "status": job["status"],
            "username": job["username"],
            "attempts": job["attempts"],
            "current_length": job["current_length"],
            "latest_guess": job["latest_guess"],
            "latest_hash": job["latest_hash"],
            "new_guesses": new_guesses,
            "found_password": job["found_password"],
            "elapsed": elapsed_now,
            "measured_rate": round(measured_rate),
            "is_max_speed": job.get("is_max_speed", False),
            "worker_count": job.get("worker_count", 1),
            "total_space": job["total_space"],
            "max_length": job["max_length"],
            "target_hash": job["target_hash"],
            "error": job["error"],
            # only meaningful once the job has finished, but harmless to
            # send throughout -- they stay empty until run_job populates them
            "length_counts": job["length_counts"],
            "timeline": job["timeline"],
        }

    return jsonify(payload)


@app.route("/api/stop/<job_id>", methods=["POST"])
def stop_job(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Unknown job id."}), 404
        job["stop_requested"] = True
    return jsonify({"ok": True})


if __name__ == "__main__":
    # debug=True is convenient for local development (auto-reload, tracebacks)
    # but should be turned off before deploying this anywhere beyond localhost.
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
