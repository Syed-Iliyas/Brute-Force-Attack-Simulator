# Brute Force Attack Simulator

A self-contained Flask web app that demonstrates how an exhaustive
("brute force") password attack works against a SHA-256 hash — built as
a cybersecurity learning project, not a tool for attacking anyone else's
accounts. You type in a password, the app hashes it, and then a search
loop tries candidate strings in increasing length order until one of
them hashes to the same value.

## Features

- Password input, hashed locally with SHA-256 as the "target"
- Character set selection: lowercase, uppercase, digits, symbols (mix and match)
- Adjustable max password length (capped at 6 to keep demos fast)
- Adjustable simulated guesses-per-second, to show how attack speed changes outcomes
- Live progress bar against the full search space
- Live "guess ledger" streaming every candidate and its SHA-256 hash
- Stop button that halts the search immediately
- Final summary: target hash, password found, total attempts, total time

## Project structure

```
brute_force_sim/
├── app.py                  Flask app: brute-force engine + JSON API
├── templates/
│   └── index.html          Page markup
└── static/
    ├── style.css           Lab-console visual design
    └── app.js              Frontend logic: start/stop, polling, live UI
```

## Running it

1. Install Flask:
   ```
   pip install flask
   ```
2. Start the server:
   ```
   python app.py
   ```
3. Open `http://127.0.0.1:5000` in your browser.

## How it works

- **`/api/start`** validates the input (password isn't empty, every
  character of the password exists in the chosen character set, length
  limits are respected) and kicks off a background thread that runs the
  search loop. It returns a `job_id` plus the target SHA-256 hash and
  the total search-space size.
- The search loop (`run_job`) walks every possible string of length 1,
  then every string of length 2, and so on up to the chosen max length,
  hashing each candidate and comparing it to the target hash. This
  mirrors how a real brute-force attack explores the keyspace.
- A "guesses per second" setting throttles the loop with small sleeps so
  you can watch the attack happen at a human-readable pace instead of it
  finishing instantly.
- **`/api/status/<job_id>`** is polled by the browser every ~120ms. It
  reports attempts so far, the current candidate, percentage complete,
  and any newly generated guesses (capped per poll so very high speeds
  don't flood the response).
- **`/api/stop/<job_id>`** sets a flag the search loop checks frequently,
  so Stop takes effect within about a tenth of a second even at very low
  simulated speeds.
- When a match is found (or the search space is exhausted, or it's
  stopped), the job's final state includes the password, total attempts,
  and total elapsed time.

## The lesson underneath the demo

Try the same password with a small character set and a short max length
versus a larger character set and a longer length, and watch the
"search space" and "worst case" time estimate on the config panel jump
by orders of magnitude. That's the real takeaway: each additional
character of length or each additional character *class* (adding
uppercase, digits, or symbols) multiplies the attacker's workload, which
is why both length and variety matter for real passwords.

## Notes & limits

- This only ever attacks a password you type into your own browser in
  the same session — there's no way to point it at someone else's
  account or an unknown hash.
- Max password length is capped at 6 characters so the search always
  finishes in a reasonable amount of time on a single CPU core. Raise
  `MAX_ALLOWED_LENGTH` in `app.py` if you want to experiment with larger
  search spaces (just expect it to take a lot longer).
- Job state lives in memory (a plain Python dict), so it resets if you
  restart the server. That's fine for a demo; a production version would
  use a real task queue and persistent storage.
- `app.run(debug=True, ...)` is meant for local development only — turn
  debug mode off before exposing this anywhere beyond localhost.
