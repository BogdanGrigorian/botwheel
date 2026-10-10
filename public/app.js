"use strict";

const passwordInput = document.getElementById("password");
const loadBtn = document.getElementById("load-btn");
const pasteField = document.getElementById("paste-field");
const pasteArea = document.getElementById("paste-area");
const result = document.getElementById("result");
const userInfo = document.getElementById("user-info");

const lockScreen = document.getElementById("lock-screen");
const mainScreen = document.getElementById("main-screen");
const searchInput = document.getElementById("search-input");
const clearBtn = document.getElementById("clear-btn");
const suggestionsEl = document.getElementById("suggestions");
const resultsEl = document.getElementById("results");
const letterStripWrap = document.getElementById("letter-strip-wrap");
const letterStripEl = document.getElementById("letter-strip");
const zoomEl = document.getElementById("letter-zoom");
const vaultMetaEl = document.getElementById("vault-meta");
const lockBtn = document.getElementById("lock-btn");

// --- Telegram Web App integration (safe when running outside Telegram) ---
const tg = window.Telegram?.WebApp;

if (tg) {
  tg.ready();
  tg.expand();

  // Match Telegram's native theme
  tg.setHeaderColor(tg.themeParams.bg_color || "#17212b");
  tg.setBackgroundColor(tg.themeParams.bg_color || "#0e1621");

  const user = tg.initDataUnsafe?.user;
  if (user) {
    userInfo.textContent = `Logged in as ${user.first_name || "user"} (@${user.username || "no username"})`;
  } else {
    userInfo.textContent = "Running inside Telegram (user data unavailable).";
  }
} else {
  userInfo.textContent = "Running in a browser — open this app through your Telegram bot to get full integration.";
}

// --- State ---
const state = {
  records: [],   // { id, n, u, o, lowerN, lowerU, lowerO, first }
  query: "",
  debounce: null,
};

// --- Helpers ---
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function highlight(text, q) {
  const esc = escapeHtml(text);
  if (!q) return esc;
  const escQ = escapeHtml(q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return esc.replace(new RegExp("(" + escQ + ")", "ig"), "<mark>$1</mark>");
}

function truncate(s, n) {
  s = String(s || "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function firstLetter(name) {
  const ch = String(name || "").trim().charAt(0).toUpperCase();
  return /[A-Z]/.test(ch) ? ch : "#";
}

// Lower score = better match; Infinity = no match.
function matchScore(rec, q) {
  const n = rec.lowerN;
  if (n === q) return 0;
  if (n.startsWith(q)) return 1;
  const idx = n.indexOf(q);
  if (idx > 0 && !/[a-z0-9]/.test(n[idx - 1])) return 2; // word start in name
  if (idx !== -1) return 3;                               // substring in name
  const u = rec.lowerU;
  if (u.startsWith(q)) return 4;
  if (u.includes(q)) return 5;
  if (rec.lowerO.includes(q)) return 6;
  return Infinity;
}

// --- Unlock / lock ---
// v2 record: { n, u, o, s } — n mandatory, u/o optional, s = encrypted username\0password.
// v1 record: { r, t, s } — migrate r -> name, t -> notes.
function normalizeEntry(e) {
  if (e.n !== undefined) {
    return { n: e.n || "", u: e.u || "", o: e.o || "", s: e.s || "" };
  }
  return { n: e.r || "", u: "", o: e.t || "", s: e.s || "" };
}

function buildIndex(entries) {
  const records = (entries || []).map((e, i) => {
    const rec = normalizeEntry(e);
    return {
      id: i,
      n: rec.n,
      u: rec.u,
      o: rec.o,
      lowerN: rec.n.toLowerCase(),
      lowerU: rec.u.toLowerCase(),
      lowerO: rec.o.toLowerCase(),
      first: firstLetter(rec.n),
    };
  });
  records.sort((a, b) => a.lowerN.localeCompare(b.lowerN));
  state.records = records;
}

function enterMainScreen(entries) {
  buildIndex(entries);
  state.query = "";
  searchInput.value = "";
  vaultMetaEl.textContent = `${state.records.length} record${state.records.length === 1 ? "" : "s"}`;
  userInfo.hidden = true;
  lockScreen.hidden = true;
  mainScreen.hidden = false;
  render();
  searchInput.focus();
}

function lock() {
  state.records = [];
  state.query = "";
  searchInput.value = "";
  passwordInput.value = "";
  result.hidden = true;
  mainScreen.hidden = true;
  lockScreen.hidden = false;
  userInfo.hidden = false;
}

// --- Rendering ---
function render() {
  renderSuggestions();
  renderResults();
  clearBtn.hidden = !state.query;
}

function renderSuggestions() {
  suggestionsEl.innerHTML = "";
  const q = state.query.trim().toLowerCase();
  if (!q) {
    suggestionsEl.hidden = true;
    return;
  }

  const scored = state.records
    .map((rec) => ({ rec, score: matchScore(rec, q) }))
    .filter((m) => m.score !== Infinity)
    .sort((a, b) => a.score - b.score || a.rec.lowerN.localeCompare(b.rec.lowerN))
    .slice(0, 5);

  if (!scored.length) {
    suggestionsEl.hidden = true;
    return;
  }
  suggestionsEl.hidden = false;

  const group = document.createElement("div");
  group.className = "suggestion-group";
  group.textContent = "Matches";
  suggestionsEl.appendChild(group);

  for (const s of scored) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "suggestion-item";
    item.innerHTML = highlight(s.rec.n, q);
    item.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      state.query = s.rec.n;
      searchInput.value = s.rec.n;
      render();
    });
    suggestionsEl.appendChild(item);
  }
}

function renderResults() {
  resultsEl.innerHTML = "";
  const q = state.query.trim().toLowerCase();

  let rows = [];
  if (q) {
    rows = state.records
      .map((rec) => ({ rec, score: matchScore(rec, q) }))
      .filter((m) => m.score !== Infinity)
      .sort((a, b) => a.score - b.score || a.rec.lowerN.localeCompare(b.rec.lowerN))
      .map((m) => m.rec);
    letterStripWrap.hidden = true;
    for (const rec of rows) resultsEl.appendChild(resultItem(rec, q));
  } else {
    rows = state.records.slice().sort((a, b) => a.lowerN.localeCompare(b.lowerN));
    letterStripWrap.hidden = false;
    renderLetterStrip(rows);
    for (const rec of rows) resultsEl.appendChild(resultItem(rec, ""));
  }

  if (!rows.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No matches — try another query.";
    resultsEl.appendChild(empty);
    letterStripWrap.hidden = true;
  }
}

function resultItem(rec, q) {
  const li = document.createElement("li");
  li.className = "result-item";
  li.dataset.first = rec.first;

  const name = document.createElement("span");
  name.className = "result-name";
  name.innerHTML = highlight(rec.n, q);
  li.appendChild(name);

  const sub = [truncate(rec.u, 60), truncate(rec.o, 60)].filter(Boolean);
  if (sub.length) {
    const line = document.createElement("span");
    line.className = "result-sub";
    line.textContent = sub.join(" · ");
    li.appendChild(line);
  }
  return li;
}

function renderLetterStrip(rows) {
  letterStripEl.innerHTML = "";
  const letters = [];
  for (const rec of rows) {
    if (!letters.includes(rec.first)) letters.push(rec.first);
  }
  letters.sort((a, b) => {
    if (a === "#") return 1;
    if (b === "#") return -1;
    return a.localeCompare(b);
  });
  for (const letter of letters) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "strip-letter";
    btn.dataset.letter = letter;
    btn.textContent = letter;
    letterStripEl.appendChild(btn);
  }
}

function jumpTo(letter) {
  const target = resultsEl.querySelector('[data-first="' + letter + '"]');
  if (target) target.scrollIntoView({ block: "start" });
}

function showZoom(letterEl) {
  const wrapRect = letterStripWrap.getBoundingClientRect();
  const rect = letterEl.getBoundingClientRect();
  zoomEl.textContent = letterEl.dataset.letter;
  zoomEl.hidden = false;
  const maxLeft = wrapRect.width - zoomEl.offsetWidth;
  const left = rect.left - wrapRect.left + rect.width / 2 - zoomEl.offsetWidth / 2;
  zoomEl.style.left = Math.max(0, Math.min(maxLeft, Math.round(left))) + "px";
}

function hideZoom() {
  zoomEl.hidden = true;
}

function stripLetterFromPoint(e) {
  const el = document.elementFromPoint(e.clientX, e.clientY);
  return el && el.closest ? el.closest(".strip-letter") : null;
}

// --- UI helpers ---
function showResult(message, isError) {
  result.hidden = false;
  result.textContent = message;
  result.classList.toggle("error", !!isError);
  result.classList.toggle("success", !isError);
}

function showPasteFallback() {
  pasteField.hidden = false;
  pasteArea.focus();
}

function setBusy(busy) {
  loadBtn.disabled = busy;
}

// --- Load / decrypt ---
async function load() {
  if (loadBtn.disabled) return;
  setBusy(true);

  try {
    const password = passwordInput.value;
    if (!password) {
      showResult("Enter the password (encryption key).", true);
      return;
    }

    const pasted = pasteArea.value.trim();
    let blobText = pasted;
    if (!blobText) {
      if (navigator.clipboard && navigator.clipboard.readText) {
        try {
          blobText = await navigator.clipboard.readText();
        } catch (e) {
          blobText = null;
        }
      }
    }

    if (!blobText || !blobText.trim()) {
      showResult("Clipboard is empty or unavailable — paste the vault message below.", true);
      showPasteFallback();
      return;
    }

    showResult("Decrypting…");
    const vault = await window.CryptoCore.decryptDatabase(blobText, password);
    result.hidden = true;
    enterMainScreen(vault.entries);
  } catch (err) {
    showResult("Failed to open vault: " + (err && err.message ? err.message : err), true);
  } finally {
    setBusy(false);
  }
}

// --- Events ---
loadBtn.addEventListener("click", load);
lockBtn.addEventListener("click", lock);

passwordInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") load();
});

searchInput.addEventListener("input", () => {
  clearTimeout(state.debounce);
  state.debounce = setTimeout(() => {
    state.query = searchInput.value;
    render();
  }, 120);
});

searchInput.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    searchInput.value = "";
    state.query = "";
    render();
  }
});

clearBtn.addEventListener("click", () => {
  searchInput.value = "";
  state.query = "";
  render();
  searchInput.focus();
});

// Letter strip: tap to jump, press-and-hold to show a magnified letter.
let holdTimer = null;
let stripActiveLetter = null;

letterStripEl.addEventListener("pointerdown", (e) => {
  const letter = stripLetterFromPoint(e);
  if (!letter) return;
  e.preventDefault();
  letterStripEl.setPointerCapture(e.pointerId);
  stripActiveLetter = letter;
  jumpTo(letter.dataset.letter);
  holdTimer = setTimeout(() => {
    if (stripActiveLetter) showZoom(stripActiveLetter);
  }, 150);

  const move = (ev) => {
    const l = stripLetterFromPoint(ev);
    if (!l) return;
    stripActiveLetter = l;
    jumpTo(l.dataset.letter);
    if (!zoomEl.hidden) showZoom(l);
  };
  const up = () => {
    clearTimeout(holdTimer);
    hideZoom();
    stripActiveLetter = null;
    letterStripEl.removeEventListener("pointermove", move);
    letterStripEl.removeEventListener("pointerup", up);
    letterStripEl.removeEventListener("pointercancel", up);
  };
  letterStripEl.addEventListener("pointermove", move);
  letterStripEl.addEventListener("pointerup", up);
  letterStripEl.addEventListener("pointercancel", up);
});
