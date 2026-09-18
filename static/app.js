(function () {
  "use strict";

  // ---- element refs ----
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  const derivedLengthEl = document.getElementById("derived-length");
  const gpsSlider = document.getElementById("gps");
  const gpsVal = document.getElementById("gps_val");
  const maxSpeedToggle = document.getElementById("max-speed-toggle");
  const searchSpacePreview = document.getElementById("search-space-preview");
  const timeWarning = document.getElementById("time-warning");
  const timeWarningText = document.getElementById("time-warning-text");

  const startBtn = document.getElementById("start-btn");
  const stopBtn = document.getElementById("stop-btn");
  const errorMsg = document.getElementById("error-msg");

  const statusChip = document.getElementById("status-chip");
  const statusChipLabel = document.getElementById("status-chip-label");

  const targetUsernameEl = document.getElementById("target-username");
  const targetHashEl = document.getElementById("target-hash");
  const progressFill = document.getElementById("progress-fill");
  const progressPercent = document.getElementById("progress-percent");
  const progressCurrentLabel = document.getElementById("progress-current-label");

  const statAttempts = document.getElementById("stat-attempts");
  const statElapsed = document.getElementById("stat-elapsed");
  const statMeasuredRate = document.getElementById("stat-measured-rate");
  const statCurrentGuess = document.getElementById("stat-current-guess");
  const statSearchSpace = document.getElementById("stat-search-space");

  const resultBanner = document.getElementById("result-banner");
  const resultTitle = document.getElementById("result-title");
  const resultDetails = document.getElementById("result-details");

  const chartsBlock = document.getElementById("charts-block");
  const chartTimeline = document.getElementById("chart-timeline");
  const chartLengths = document.getElementById("chart-lengths");

  const ledgerBody = document.getElementById("ledger-body");
  const ledgerEmpty = document.getElementById("ledger-empty");

  let currentJobId = null;
  let pollHandle = null;
  let totalSpace = 0;
  let rowCount = 0;
  const MAX_LEDGER_ROWS = 500;

  // The simulator always searches the full combined alphabet -- lowercase,
  // uppercase, digits, and the symbol set the backend uses. Keep this in
  // sync with FULL_CHARSET in app.py.
  const FULL_CHARSET_SIZE = 76;
  const DEFAULT_MIN_LEN = 1;
  const DEFAULT_MAX_LEN = 10;
  const parsedMinLen = parseInt(passwordInput.getAttribute("minlength"), 10);
  const parsedMaxLen = parseInt(passwordInput.getAttribute("maxlength"), 10);
  const MIN_LEN = Number.isFinite(parsedMinLen) ? parsedMinLen : DEFAULT_MIN_LEN;
  const MAX_LEN = Number.isFinite(parsedMaxLen) ? parsedMaxLen : DEFAULT_MAX_LEN;
  const MAX_SPEED_SENTINEL = -1;

  // ---- helpers ----
  function fmtNumber(n) {
    return n.toLocaleString("en-US");
  }

  function totalCombinations(charsetSize, maxLen) {
    let total = 0;
    for (let len = 1; len <= maxLen; len++) {
      total += Math.pow(charsetSize, len);
    }
    return total;
  }

  function updateSearchSpacePreview() {
    const len = passwordInput.value.length;

    derivedLengthEl.textContent = len === 1 ? "1 character" : `${len} characters`;

    if (len === 0) {
      searchSpacePreview.textContent = "Search space: type a password above to see the estimate";
      timeWarning.hidden = true;
      return;
    }

    const total = totalCombinations(FULL_CHARSET_SIZE, len);

    if (maxSpeedToggle.checked) {
      // No honest worst-case estimate exists for MAX speed -- the real rate
      // depends on this machine's CPU and isn't known until the job is
      // actually running, so we don't show a number we'd have to make up.
      searchSpacePreview.textContent =
        `Search space: ${fmtNumber(total)} possible strings (full ${FULL_CHARSET_SIZE}-character alphabet, ` +
        `lengths 1\u2013${len}) \u2014 MAX speed mode: real rate will be measured once the attack starts`;
      timeWarning.hidden = true;
      return;
    }

    const gps = parseInt(gpsSlider.value, 10);
    const worstCaseSeconds = gps > 0 ? total / gps : Infinity;

    searchSpacePreview.textContent =
      `Search space: ${fmtNumber(total)} possible strings (full ${FULL_CHARSET_SIZE}-character alphabet, ` +
      `lengths 1\u2013${len}) \u2014 worst case ${fmtDuration(worstCaseSeconds)} at this speed`;

    // Warn based on the actual estimated time, not the password length in
    // isolation -- a short password at a slow simulated speed can also take
    // a while, and a longer one at max speed might still be borderline. One
    // hour is a reasonable line between "this demo will finish" and "this
    // is here to make a point about scale".
    const WARNING_THRESHOLD_SECONDS = 3600;
    if (worstCaseSeconds > WARNING_THRESHOLD_SECONDS) {
      timeWarning.hidden = false;
      timeWarningText.innerHTML =
        `At this length and speed, exhausting the full search space would take <b>${fmtDuration(worstCaseSeconds)}</b>. ` +
        `Real brute-force runs at longer lengths almost never finish on their own &mdash; that scale is the point. ` +
        `You can still launch and watch it work, then stop whenever you like.`;
    } else {
      timeWarning.hidden = true;
    }
  }

  function fmtDuration(seconds) {
    if (!isFinite(seconds)) return "effectively forever";
    if (seconds < 1) return "under 1s";
    if (seconds < 60) return `${seconds.toFixed(0)}s`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hr`;
    if (seconds < 31536000) return `${(seconds / 86400).toFixed(1)} days`;
    return `${(seconds / 31536000).toFixed(1)} years`;
  }

  function setStatus(state, label) {
    statusChip.dataset.state = state;
    statusChipLabel.textContent = label;
  }

  function resetLedger() {
    ledgerBody.innerHTML = "";
    rowCount = 0;
    ledgerBody.appendChild(ledgerEmpty);
    ledgerEmpty.hidden = false;
  }

  function appendLedgerRows(entries, targetHash, finalMatch) {
    if (entries.length === 0) return;
    ledgerEmpty.hidden = true;

    const frag = document.createDocumentFragment();
    entries.forEach(entry => {
      const guess = entry.guess;
      const hash = entry.hash;
      rowCount += 1;
      const row = document.createElement("div");
      row.className = "ledger-row";

      const isMatch = finalMatch && guess === finalMatch && hash === targetHash;
      if (isMatch) row.classList.add("is-match");

      const nEl = document.createElement("span");
      nEl.className = "col-n";
      nEl.textContent = rowCount;

      const guessEl = document.createElement("span");
      guessEl.className = "col-guess";
      guessEl.textContent = guess;

      const hashEl = document.createElement("span");
      hashEl.className = "col-hash";
      hashEl.textContent = hash;
      hashEl.title = hash;

      const matchEl = document.createElement("span");
      matchEl.className = "col-match";
      matchEl.textContent = isMatch ? "YES" : "no";

      row.appendChild(nEl);
      row.appendChild(guessEl);
      row.appendChild(hashEl);
      row.appendChild(matchEl);
      frag.appendChild(row);
    });

    ledgerBody.appendChild(frag);

    // trim from the top if too long
    while (ledgerBody.children.length > MAX_LEDGER_ROWS + 1) {
      // +1 to account for the (hidden) empty-state node still present
      const first = ledgerBody.querySelector(".ledger-row");
      if (first) first.remove();
      else break;
    }

    ledgerBody.scrollTop = ledgerBody.scrollHeight;
  }

  function showError(msg) {
    errorMsg.textContent = msg;
  }

  function clearError() {
    errorMsg.textContent = "";
  }

  function setRunningUI(isRunning) {
    startBtn.disabled = isRunning;
    stopBtn.disabled = !isRunning;
    usernameInput.disabled = isRunning;
    passwordInput.disabled = isRunning;
    gpsSlider.disabled = isRunning || maxSpeedToggle.checked;
    maxSpeedToggle.disabled = isRunning;
  }

  function resetReadout() {
    targetUsernameEl.textContent = "\u2014";
    targetHashEl.textContent = "\u2014";
    progressFill.style.width = "0%";
    progressPercent.textContent = "0%";
    progressCurrentLabel.textContent = "Trying length 1";
    statAttempts.textContent = "0";
    statElapsed.textContent = "0.0s";
    statMeasuredRate.textContent = "\u2014";
    statCurrentGuess.textContent = "\u2014";
    statSearchSpace.textContent = "\u2014";
    resultBanner.hidden = true;
    chartsBlock.hidden = true;
    chartTimeline.innerHTML = "";
    chartLengths.innerHTML = "";
  }

  // ---- live preview listeners ----
  passwordInput.addEventListener("input", () => {
    updateSearchSpacePreview();
  });
  gpsSlider.addEventListener("input", () => {
    gpsVal.textContent = fmtNumber(parseInt(gpsSlider.value, 10));
    updateSearchSpacePreview();
  });
  maxSpeedToggle.addEventListener("change", () => {
    gpsSlider.disabled = maxSpeedToggle.checked;
    updateSearchSpacePreview();
  });

  // ---- start ----
  startBtn.addEventListener("click", async () => {
    clearError();
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    const gps = maxSpeedToggle.checked ? MAX_SPEED_SENTINEL : parseInt(gpsSlider.value, 10);

    if (!password) {
      showError("Enter a password to attack first.");
      return;
    }
    if (password.length < MIN_LEN || password.length > MAX_LEN) {
      showError(`Password must be between ${MIN_LEN} and ${MAX_LEN} characters long.`);
      return;
    }

    resetReadout();
    resetLedger();
    setRunningUI(true);
    setStatus("running", "RUNNING");

    let resp;
    try {
      resp = await fetch("/api/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, gps }),
      });
    } catch (e) {
      showError("Could not reach the server. Is it running?");
      setRunningUI(false);
      setStatus("error", "ERROR");
      return;
    }

    const data = await resp.json();
    if (!resp.ok) {
      showError(data.error || "Something went wrong starting the attack.");
      setRunningUI(false);
      setStatus("idle", "IDLE");
      return;
    }

    currentJobId = data.job_id;
    totalSpace = data.total_space;
    targetUsernameEl.textContent = data.username ? data.username : "\u2014 (none given)";
    targetHashEl.textContent = data.target_hash;
    statSearchSpace.textContent = fmtNumber(totalSpace);

    pollHandle = setInterval(pollStatus, 120);
  });

  // ---- stop ----
  stopBtn.addEventListener("click", async () => {
    if (!currentJobId) return;
    try {
      await fetch(`/api/stop/${currentJobId}`, { method: "POST" });
    } catch (e) {
      // best-effort; polling will still pick up final state if reachable
    }
  });

  // ---- poll ----
  async function pollStatus() {
    if (!currentJobId) return;
    let resp;
    try {
      resp = await fetch(`/api/status/${currentJobId}`);
    } catch (e) {
      return; // transient network hiccup; try again next tick
    }
    if (!resp.ok) return;
    const data = await resp.json();

    statAttempts.textContent = fmtNumber(data.attempts);
    statElapsed.textContent = `${data.elapsed.toFixed(1)}s`;
    if (data.measured_rate) {
      const rateLabel = fmtNumber(data.measured_rate) + "/s";
      statMeasuredRate.textContent = data.is_max_speed && data.worker_count > 1
        ? `${rateLabel} (${data.worker_count} cores)`
        : rateLabel;
    } else {
      statMeasuredRate.textContent = "\u2014";
    }
    statCurrentGuess.textContent = data.latest_guess || "\u2014";
    progressCurrentLabel.textContent = `Trying length ${data.current_length}`;

    const pct = totalSpace > 0 ? Math.min(100, (data.attempts / totalSpace) * 100) : 0;
    progressFill.style.width = `${pct}%`;
    progressPercent.textContent = `${pct.toFixed(1)}%`;

    if (data.new_guesses && data.new_guesses.length > 0) {
      appendLedgerRows(data.new_guesses, data.target_hash, data.found_password);
    }

    if (data.status === "found" || data.status === "stopped" || data.status === "exhausted" || data.status === "error") {
      clearInterval(pollHandle);
      pollHandle = null;
      setRunningUI(false);

      progressFill.style.width = data.status === "found" ? "100%" : progressFill.style.width;
      if (data.status === "found") progressPercent.textContent = "100%";

      resultBanner.hidden = false;
      resultBanner.dataset.state = data.status;

      if (data.status === "found") {
        setStatus("found", "MATCH FOUND");
        resultTitle.textContent = "\u2713 Password cracked";
        const rateNote = data.is_max_speed && data.worker_count > 1
          ? `${fmtNumber(data.measured_rate)}/s avg (${data.worker_count} cores)`
          : `${fmtNumber(data.measured_rate)}/s avg`;
        resultDetails.innerHTML = `
          <div>Username: <b>${escapeHtml(data.username || "(none given)")}</b></div>
          <div>Password found: <b>${escapeHtml(data.found_password)}</b></div>
          <div>Total attempts: <b>${fmtNumber(data.attempts)}</b></div>
          <div>Total time: <b>${data.elapsed.toFixed(3)}s</b></div>
          <div>Average rate: <b>${rateNote}</b></div>
          <div>Target hash: <b>${data.target_hash}</b></div>
        `;
        renderCharts(data.timeline, data.length_counts, data.max_length);
      } else if (data.status === "stopped") {
        setStatus("stopped", "STOPPED");
        resultTitle.textContent = "Attack stopped manually";
        resultDetails.innerHTML = `
          <div>Attempts before stopping: <b>${fmtNumber(data.attempts)}</b></div>
          <div>Elapsed: <b>${data.elapsed.toFixed(3)}s</b></div>
        `;
      } else if (data.status === "exhausted") {
        setStatus("stopped", "NO MATCH");
        resultTitle.textContent = "Search space exhausted \u2014 no match";
        resultDetails.innerHTML = `
          <div>Total attempts: <b>${fmtNumber(data.attempts)}</b></div>
          <div>Total time: <b>${data.elapsed.toFixed(3)}s</b></div>
          <div colspan="2">The password isn't reachable within this length range.</div>
        `;
      } else if (data.status === "error") {
        setStatus("error", "ERROR");
        resultTitle.textContent = "Something went wrong";
        resultDetails.innerHTML = `<div>${escapeHtml(data.error || "Unknown error")}</div>`;
      }
    }
  }

  // ---- post-crack charts ----
  const SVG_NS = "http://www.w3.org/2000/svg";
  const CHART_W = 600;
  const CHART_H = 180;
  const CHART_PAD = { top: 14, right: 14, bottom: 24, left: 44 };

  function svgEl(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(k => el.setAttribute(k, attrs[k]));
    return el;
  }

  function renderCharts(timeline, lengthCounts, maxLength) {
    chartsBlock.hidden = false;
    renderTimelineChart(timeline || []);
    renderLengthChart(lengthCounts || {}, maxLength || 0);
  }

  // Line + filled area showing cumulative attempts climbing over elapsed time.
  function renderTimelineChart(timeline) {
    chartTimeline.innerHTML = "";
    chartTimeline.setAttribute("viewBox", `0 0 ${CHART_W} ${CHART_H}`);

    if (!timeline.length) {
      chartTimeline.appendChild(svgEl("text", {
        x: CHART_W / 2, y: CHART_H / 2, "text-anchor": "middle", class: "chart-label",
      })).textContent = "No timeline data (search finished too fast to sample)";
      return;
    }

    const plotW = CHART_W - CHART_PAD.left - CHART_PAD.right;
    const plotH = CHART_H - CHART_PAD.top - CHART_PAD.bottom;
    const maxT = Math.max(timeline[timeline.length - 1].t, 0.001);
    const maxAttempts = Math.max(timeline[timeline.length - 1].attempts, 1);

    const xAt = t => CHART_PAD.left + (t / maxT) * plotW;
    const yAt = a => CHART_PAD.top + plotH - (a / maxAttempts) * plotH;

    // axes
    chartTimeline.appendChild(svgEl("line", {
      x1: CHART_PAD.left, y1: CHART_PAD.top, x2: CHART_PAD.left, y2: CHART_PAD.top + plotH, class: "chart-axis",
    }));
    chartTimeline.appendChild(svgEl("line", {
      x1: CHART_PAD.left, y1: CHART_PAD.top + plotH, x2: CHART_PAD.left + plotW, y2: CHART_PAD.top + plotH, class: "chart-axis",
    }));

    // line + filled area path
    let linePoints = timeline.map(p => `${xAt(p.t)},${yAt(p.attempts)}`).join(" ");
    const areaPath = `M${xAt(0)},${yAt(0)} L${linePoints} L${xAt(timeline[timeline.length - 1].t)},${yAt(0)} Z`;
    chartTimeline.appendChild(svgEl("path", { d: areaPath, class: "chart-area" }));
    chartTimeline.appendChild(svgEl("polyline", { points: linePoints, class: "chart-line" }));

    // labels: y-axis max, x-axis max time
    const yLabel = chartTimeline.appendChild(svgEl("text", {
      x: 6, y: CHART_PAD.top + 4, class: "chart-value-label",
    }));
    yLabel.textContent = fmtNumber(maxAttempts);

    const xLabel = chartTimeline.appendChild(svgEl("text", {
      x: CHART_PAD.left + plotW, y: CHART_H - 6, "text-anchor": "end", class: "chart-label",
    }));
    xLabel.textContent = `${maxT.toFixed(2)}s`;

    const xLabelStart = chartTimeline.appendChild(svgEl("text", {
      x: CHART_PAD.left, y: CHART_H - 6, class: "chart-label",
    }));
    xLabelStart.textContent = "0s";
  }

  // Bar chart showing how many candidates were tried at each password length,
  // 1 through the cracked password's own length.
  function renderLengthChart(lengthCounts, maxLength) {
    chartLengths.innerHTML = "";
    chartLengths.setAttribute("viewBox", `0 0 ${CHART_W} ${CHART_H}`);

    const lengths = [];
    for (let l = 1; l <= maxLength; l++) lengths.push(l);

    if (!lengths.length) {
      chartLengths.appendChild(svgEl("text", {
        x: CHART_W / 2, y: CHART_H / 2, "text-anchor": "middle", class: "chart-label",
      })).textContent = "No length data available";
      return;
    }

    const plotW = CHART_W - CHART_PAD.left - CHART_PAD.right;
    const plotH = CHART_H - CHART_PAD.top - CHART_PAD.bottom;
    const counts = lengths.map(l => lengthCounts[l] || lengthCounts[String(l)] || 0);
    const maxCount = Math.max(...counts, 1);

    const barGap = 10;
    const barW = (plotW - barGap * (lengths.length - 1)) / lengths.length;

    chartLengths.appendChild(svgEl("line", {
      x1: CHART_PAD.left, y1: CHART_PAD.top, x2: CHART_PAD.left, y2: CHART_PAD.top + plotH, class: "chart-axis",
    }));
    chartLengths.appendChild(svgEl("line", {
      x1: CHART_PAD.left, y1: CHART_PAD.top + plotH, x2: CHART_PAD.left + plotW, y2: CHART_PAD.top + plotH, class: "chart-axis",
    }));

    lengths.forEach((len, i) => {
      const count = counts[i];
      const barH = (count / maxCount) * plotH;
      const x = CHART_PAD.left + i * (barW + barGap);
      const y = CHART_PAD.top + plotH - barH;
      const isFinal = len === maxLength;

      chartLengths.appendChild(svgEl("rect", {
        x, y, width: barW, height: Math.max(barH, 1),
        class: isFinal ? "chart-bar is-final" : "chart-bar",
        rx: 3,
      }));

      chartLengths.appendChild(svgEl("text", {
        x: x + barW / 2, y: CHART_H - 6, "text-anchor": "middle", class: "chart-label",
      })).textContent = `len ${len}`;

      chartLengths.appendChild(svgEl("text", {
        x: x + barW / 2, y: y - 4, "text-anchor": "middle", class: "chart-value-label",
      })).textContent = fmtNumber(count);
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // ---- init ----
  updateSearchSpacePreview();
})();
