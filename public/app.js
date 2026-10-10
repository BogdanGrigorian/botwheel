"use strict";

const passwordInput = document.getElementById("password");
const usernameInput = document.getElementById("username");
const loadBtn = document.getElementById("load-btn");
const lockForm = document.getElementById("lock-form");
const pasteField = document.getElementById("paste-field");
const pasteArea = document.getElementById("paste-area");
const result = document.getElementById("result");
const userInfo = document.getElementById("user-info");

const lockScreen = document.getElementById("lock-screen");
const mainScreen = document.getElementById("main-screen");
const searchInput = document.getElementById("search-input");
const clearBtn = document.getElementById("clear-btn");
const resultsEl = document.getElementById("results");
const letterStripWrap = document.getElementById("letter-strip-wrap");
const letterStripEl = document.getElementById("letter-strip");
const filterBar = document.getElementById("filter-bar");
const filterLabel = document.getElementById("filter-label");
const resetBtn = document.getElementById("reset-btn");
const vaultMetaEl = document.getElementById("vault-meta");
const lockBtn = document.getElementById("lock-btn");

const detailsScreen = document.getElementById("details-screen");
const detailsBack = document.getElementById("details-back");
const detailsStatus = document.getElementById("details-status");
const detailsName = document.getElementById("details-name");
const detailsUrl = document.getElementById("details-url");
const detailsNotes = document.getElementById("details-notes");
const detailsLogin = document.getElementById("details-login");
const detailsEmail = document.getElementById("details-email");
const detailsPassword = document.getElementById("details-password");
const revealPasswordBtn = document.getElementById("reveal-password");

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

// Prefill the username from Telegram (used only to give password managers a
// stable identity; decryption relies solely on the password).
if (!usernameInput.value) {
  usernameInput.value = tg && tg.initDataUnsafe && tg.initDataUnsafe.user
    ? (tg.initDataUnsafe.user.username || String(tg.initDataUnsafe.user.id))
    : "";
}

// --- State ---
const state = {
  records: [],   // { id, n, u, o, l, e, s, lowerN, lowerU, lowerO, lowerL, lowerE, first }
  query: "",
  letter: null,  // active quick-search letter filter
  password: "",  // vault encryption key (kept in memory while unlocked)
  vaultSalt: null, // Uint8Array — per-vault salt for credential keys
  key: null,     // cached credential CryptoKey (derived lazily)
  selected: null, // record id currently shown in the details view
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
  if (rec.lowerL.includes(q)) return 7;
  if (rec.lowerE.includes(q)) return 8;
  return Infinity;
}

// --- Unlock / lock ---
// v3 record: { n, u, o, l, e, s } — n mandatory, s = encrypted password, l/e optional plaintext.
// v2 record: { n, u, o, s } — s = encrypted "username\0password".
// v1 record: { r, t, s } — migrate r -> name, t -> notes.
function normalizeEntry(e) {
  if (e.n !== undefined) {
    return { n: e.n || "", u: e.u || "", o: e.o || "", l: e.l || "", e: e.e || "", s: e.s || "" };
  }
  return { n: e.r || "", u: "", o: e.t || "", l: "", e: "", s: e.s || "" };
}

function buildIndex(entries) {
  const records = (entries || []).map((e, i) => {
    const rec = normalizeEntry(e);
    return {
      id: i,
      n: rec.n,
      u: rec.u,
      o: rec.o,
      l: rec.l,
      e: rec.e,
      s: rec.s,
      lowerN: rec.n.toLowerCase(),
      lowerU: rec.u.toLowerCase(),
      lowerO: rec.o.toLowerCase(),
      lowerL: rec.l.toLowerCase(),
      lowerE: rec.e.toLowerCase(),
      first: firstLetter(rec.n),
    };
  });
  records.sort((a, b) => a.lowerN.localeCompare(b.lowerN));
  state.records = records;
}

function enterMainScreen(entries) {
  buildIndex(entries);
  state.query = "";
  state.letter = null;
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
  state.letter = null;
  state.password = "";
  state.vaultSalt = null;
  state.key = null;
  state.selected = null;
  searchInput.value = "";
  passwordInput.value = "";
  result.hidden = true;
  detailsScreen.hidden = true;
  mainScreen.hidden = true;
  lockScreen.hidden = false;
  userInfo.hidden = false;
}

// --- Rendering ---
function render() {
  renderResults();
  renderFilterBar();
  clearBtn.hidden = !state.query;
}

function renderFilterBar() {
  const active = state.query || state.letter;
  filterBar.hidden = !active;
  if (!active) return;
  filterLabel.textContent = state.letter
    ? `Filter: names starting with “${state.letter}”`
    : `Search: “${state.query}”`;
}

function resetFilter() {
  state.query = "";
  state.letter = null;
  searchInput.value = "";
  render();
  searchInput.focus();
}

function renderResults() {
  resultsEl.innerHTML = "";
  const q = state.query.trim().toLowerCase();

  let rows = [];
  if (state.letter) {
    rows = state.records
      .filter((rec) => rec.first === state.letter)
      .sort((a, b) => a.lowerN.localeCompare(b.lowerN));
    letterStripWrap.hidden = false;
    renderLetterStrip(state.letter);
    for (const rec of rows) resultsEl.appendChild(resultItem(rec, ""));
  } else if (q) {
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
    renderLetterStrip(null);
    for (const rec of rows) resultsEl.appendChild(resultItem(rec, ""));
  }

  if (!rows.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No matches — try another query.";
    resultsEl.appendChild(empty);
    if (!state.letter) letterStripWrap.hidden = true;
  }
}

function resultItem(rec, q) {
  const li = document.createElement("li");
  li.className = "result-item";
  li.dataset.first = rec.first;
  li.tabIndex = 0;
  li.setAttribute("role", "button");
  li.setAttribute("aria-label", "Open record " + rec.n);

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

  const chevron = document.createElement("span");
  chevron.className = "result-chevron";
  chevron.setAttribute("aria-hidden", "true");
  chevron.textContent = "›";
  li.appendChild(chevron);

  li.addEventListener("click", () => openRecord(rec));
  li.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openRecord(rec);
    }
  });

  return li;
}

function renderLetterStrip(activeLetter) {
  letterStripEl.innerHTML = "";
  const letters = [];
  for (const rec of state.records) {
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
    btn.className = "strip-letter" + (letter === activeLetter ? " active" : "");
    btn.dataset.letter = letter;
    btn.textContent = letter;
    btn.addEventListener("click", () => {
      state.letter = state.letter === letter ? null : letter;
      state.query = "";
      searchInput.value = "";
      render();
    });
    letterStripEl.appendChild(btn);
  }
}

// --- Record details ---
let detailsData = { login: "", email: "", password: "" };
let passwordRevealed = false;

async function getCredentialKey() {
  if (!state.key) {
    state.key = await window.CryptoCore.deriveKey(state.password, state.vaultSalt);
  }
  return state.key;
}

async function openRecord(rec) {
  const id = rec.id;
  state.selected = id;

  detailsName.textContent = rec.n || "—";

  if (rec.u) {
    detailsUrl.textContent = rec.u;
    detailsUrl.setAttribute("href", /^https?:\/\//i.test(rec.u) ? rec.u : "https://" + rec.u);
  } else {
    detailsUrl.textContent = "—";
    detailsUrl.removeAttribute("href");
  }

  detailsNotes.textContent = rec.o || "—";
  detailsLogin.textContent = rec.l || "—";
  detailsEmail.textContent = rec.e || "—";

  detailsPassword.textContent = "••••••••";
  detailsData = { login: rec.l || "", email: rec.e || "", password: "" };
  passwordRevealed = false;
  revealPasswordBtn.textContent = "Show";
  detailsStatus.hidden = true;

  mainScreen.hidden = true;
  detailsScreen.hidden = false;

  try {
    const key = await getCredentialKey();
    const secret = await window.CryptoCore.decryptWithKey(key, rec.s);
    if (state.selected !== id) return; // another record was opened meanwhile
    const sep = secret.indexOf("\u0000");
    if (sep !== -1) {
      // legacy v1/v2: "username\0password"
      detailsData.login = secret.slice(0, sep);
      detailsData.password = secret.slice(sep + 1);
      detailsLogin.textContent = detailsData.login || "—";
    } else {
      detailsData.password = secret;
    }
    detailsPassword.textContent = passwordRevealed
      ? detailsData.password
      : "•".repeat(Math.max(8, detailsData.password.length));
  } catch (err) {
    if (state.selected !== id) return;
    detailsData = { login: "", email: "", password: "" };
    detailsPassword.textContent = "—";
  }
}

function closeDetails() {
  detailsScreen.hidden = true;
  mainScreen.hidden = false;
  state.selected = null;
  passwordRevealed = false;
  detailsData = { login: "", email: "", password: "" };
  detailsStatus.hidden = true;
}

async function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch (e) {
      // fall through to the legacy fallback
    }
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
  } finally {
    document.body.removeChild(ta);
  }
}

let flashStatusTimer = null;

function flashStatus() {
  detailsStatus.textContent = "Copied!";
  detailsStatus.hidden = false;
  clearTimeout(flashStatusTimer);
  flashStatusTimer = setTimeout(() => {
    detailsStatus.hidden = true;
  }, 1200);
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

    // Candidate sources, in order: the clipboard buffer first, then the
    // always-visible database-string box (fallback when the buffer is empty
    // or its content is bad).
    const candidates = [];
    if (navigator.clipboard && navigator.clipboard.readText) {
      try {
        const clip = (await navigator.clipboard.readText()).trim();
        if (clip) candidates.push(clip);
      } catch (e) {
        // clipboard unavailable — fall through to the paste box
      }
    }
    const pasted = pasteArea.value.trim();
    if (pasted) candidates.push(pasted);

    if (!candidates.length) {
      showResult("Clipboard is empty or unavailable — paste the database string below.", true);
      showPasteFallback();
      return;
    }

    showResult("Decrypting…");
    let lastError = null;
    for (const blobText of candidates) {
      try {
        const vault = await window.CryptoCore.decryptDatabase(blobText, password);
        result.hidden = true;
        state.password = password;
        state.vaultSalt = vault.salt;
        state.key = null;
        enterMainScreen(vault.entries);
        return;
      } catch (err) {
        lastError = err;
      }
    }
    showResult("Failed to open vault: " + (lastError && lastError.message ? lastError.message : lastError), true);
  } catch (err) {
    showResult("Failed to open vault: " + (err && err.message ? err.message : err), true);
  } finally {
    setBusy(false);
  }
}

// --- Events ---
lockForm.addEventListener("submit", (e) => {
  e.preventDefault();
  load();
});
lockBtn.addEventListener("click", lock);

searchInput.addEventListener("input", () => {
  state.letter = null; // typing overrides the quick-letter filter
  state.query = searchInput.value;
  render();
});

searchInput.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    searchInput.value = "";
    state.query = "";
    render();
  }
});

clearBtn.addEventListener("click", resetFilter);
resetBtn.addEventListener("click", resetFilter);

detailsBack.addEventListener("click", closeDetails);

revealPasswordBtn.addEventListener("click", () => {
  passwordRevealed = !passwordRevealed;
  revealPasswordBtn.textContent = passwordRevealed ? "Hide" : "Show";
  detailsPassword.textContent = passwordRevealed
    ? detailsData.password
    : "•".repeat(Math.max(8, detailsData.password.length));
});

detailsLogin.addEventListener("click", async () => {
  await copyText(detailsData.login);
  flashStatus();
});

detailsEmail.addEventListener("click", async () => {
  await copyText(detailsData.email);
  flashStatus();
});

detailsPassword.addEventListener("click", async () => {
  await copyText(detailsData.password);
  flashStatus();
});
