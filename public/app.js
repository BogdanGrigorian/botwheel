"use strict";

// The cache-busting version of this very script (index.html loads
// "app.js?v=N"), shown on the lock screen so it is obvious which build runs.
const APP_VERSION = (function () {
  const src = (document.currentScript && document.currentScript.src) || "";
  const match = src.match(/[?&]v=([^&]+)/);
  return match ? match[1] : "";
})();

const passwordInput = document.getElementById("password");
const strengthEl = document.getElementById("strength");
const strengthFill = document.getElementById("strength-fill");
const strengthLabel = document.getElementById("strength-label");
const usernameInput = document.getElementById("username");
const loadBtn = document.getElementById("load-btn");
const lockForm = document.getElementById("lock-form");
const pasteField = document.getElementById("paste-field");
const pasteArea = document.getElementById("paste-area");
const result = document.getElementById("result");
const appVersionEl = document.getElementById("app-version");

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
const cacheBar = document.getElementById("cache-bar");
const cacheText = document.getElementById("cache-text");
const cacheRefresh = document.getElementById("cache-refresh");

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

const detailsTitle = document.getElementById("details-title");
const detailsBody = document.getElementById("details-body");
const detailsEditBtn = document.getElementById("details-edit");
const editForm = document.getElementById("edit-form");
const editName = document.getElementById("edit-name");
const editLogin = document.getElementById("edit-login");
const editEmail = document.getElementById("edit-email");
const editPassword = document.getElementById("edit-password");
const editUrl = document.getElementById("edit-url");
const editNotes = document.getElementById("edit-notes");
const editError = document.getElementById("edit-error");
const editCancel = document.getElementById("edit-cancel");
const editSaveBtn = document.getElementById("edit-save");
const editRevealBtn = document.getElementById("edit-reveal");
const addBtn = document.getElementById("add-btn");

const saveScreen = document.getElementById("save-screen");
const saveBack = document.getElementById("save-back");
const saveCommand = document.getElementById("save-command");
const saveCopy = document.getElementById("save-copy");
const saveSend = document.getElementById("save-send");
const saveHint = document.getElementById("save-hint");
const detailsDeleteBtn = document.getElementById("details-delete");

// Version of the running build (the "?v=" from this script's own URL).
if (appVersionEl) {
  appVersionEl.textContent = APP_VERSION ? "v" + APP_VERSION : "";
  appVersionEl.hidden = !APP_VERSION;
}

// --- Telegram Web App integration (safe when running outside Telegram) ---
const tg = window.Telegram?.WebApp;

if (tg) {
  tg.ready();
  tg.expand();

  // Match Telegram's native theme
  tg.setHeaderColor(tg.themeParams.bg_color || "#17212b");
  tg.setBackgroundColor(tg.themeParams.bg_color || "#0e1621");
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
  records: [],   // { id, cipher, n, u, o, l, e, p, lowerN, lowerU, lowerO, lowerL, lowerE, first }
  query: "",
  letter: null,  // active quick-search letter filter
  password: "",  // vault encryption key (kept in memory while unlocked)
  headerB64: "", // vault header (KDF params + salt), base64url
  salt: null,    // Uint8Array — per-vault salt for record keys
  kdf: null,     // vault KDF params, for record keys
  key: null,     // cached record CryptoKey (derived lazily)
  selected: null, // record id currently shown in the details view
  editing: false, // details screen is showing the edit form
  editingId: null, // id of the record being edited (null = creating a new one)
};

// One change (a record + its header + a note) must fit in a single Telegram
// message, so a record that would not is refused rather than silently lost.
const MAX_PAYLOAD = 4000;

// --- Local cache of the last inserted database ----------------------------
// The bot stamps every Mini App link it hands out with the vault's revision
// (?v=<version>&t=<updatedAtMillis>&c=<revision>). On open we compare that
// stamp with the container we cached in localStorage to decide whether the user
// still holds the latest database or must fetch it again.
//
// The comparison key is the container's 8-hex revision (it is content-based and
// survives bot restarts, unlike a wall-clock timestamp); the timestamp is still
// stored and shown to the user.
const CACHE_KEYS = {
  blob: "botwheel-vault-blob",
  c: "botwheel-vault-checksum",
  v: "botwheel-vault-version",
  t: "botwheel-vault-bot-timestamp",
  savedAt: "botwheel-vault-saved-at",
};

let serverRevision = { c: "", v: "", t: "" }; // from the URL the app was opened with
let preferredBlob = "";                        // verified cached copy, tried first

function checksumOf(blobText) {
  const s = String(blobText || "");
  const dot = s.lastIndexOf(".");
  return dot === -1 ? "" : s.slice(dot + 1);
}

function readUrlRevision() {
  const rev = { c: "", v: "", t: "" };
  const absorb = (params) => {
    if (!params) return;
    rev.c = rev.c || params.get("c") || "";
    rev.v = rev.v || params.get("v") || "";
    rev.t = rev.t || params.get("t") || "";
  };
  try { absorb(new URLSearchParams(location.search)); } catch (e) {}
  try {
    if (location.hash && location.hash.length > 1) {
      absorb(new URLSearchParams(location.hash.slice(1)));
    }
  } catch (e) {}
  const sp = tg && tg.initDataUnsafe && tg.initDataUnsafe.start_param;
  if (sp) {
    try { absorb(new URLSearchParams(sp)); } catch (e) {}
  }
  return rev;
}

function readCache() {
  try {
    const blob = localStorage.getItem(CACHE_KEYS.blob);
    if (!blob) return null;
    return {
      blob,
      c: localStorage.getItem(CACHE_KEYS.c) || "",
      v: localStorage.getItem(CACHE_KEYS.v) || "",
      t: localStorage.getItem(CACHE_KEYS.t) || "",
      savedAt: Number(localStorage.getItem(CACHE_KEYS.savedAt) || 0),
    };
  } catch (e) {
    return null;
  }
}

function writeCache(blobText) {
  try {
    const c = checksumOf(blobText);
    // Only trust the link's version/timestamp when it describes this exact blob.
    const matches = serverRevision.c && c && serverRevision.c === c;
    localStorage.setItem(CACHE_KEYS.blob, blobText);
    localStorage.setItem(CACHE_KEYS.c, c);
    localStorage.setItem(CACHE_KEYS.v, matches ? serverRevision.v : "");
    localStorage.setItem(CACHE_KEYS.t, matches ? serverRevision.t : "");
    localStorage.setItem(CACHE_KEYS.savedAt, String(Date.now()));
  } catch (e) {
    // storage unavailable — caching is best-effort
  }
}

function clearCache() {
  try {
    Object.keys(CACHE_KEYS).forEach((k) => localStorage.removeItem(CACHE_KEYS[k]));
  } catch (e) {}
  preferredBlob = "";
}

// A saved vault that hasn't reached the bot yet (see flushPending()).
const PENDING_KEY = "botwheel-vault-pending";

function readPending() {
  try { return localStorage.getItem(PENDING_KEY) || ""; } catch (e) { return ""; }
}

function setPending(payload) {
  try { localStorage.setItem(PENDING_KEY, payload); } catch (e) {}
}

function clearPending() {
  try { localStorage.removeItem(PENDING_KEY); } catch (e) {}
}

// sendData() is only delivered when the Mini App was opened from the keyboard
// button. So a change saved from an inline/menu launch is queued here and
// pushed automatically the next time the app is opened that way.
function flushPending() {
  const pending = readPending();
  if (!pending || !canSendData()) return false;
  try {
    tg.sendData(pending);
    clearPending();
    return true;
  } catch (e) {
    return false;
  }
}

// Compact "YYYY-MM-DD HH:MM" stamp so the cache line stays on one row.
function fmtStamp(ms) {
  const n = Number(ms);
  if (!n) return "";
  const d = new Date(n);
  const p = (x) => String(x).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
    " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

// "none"    — nothing cached yet (first run)
// "current" — cache matches the revision the bot advertised
// "stale"   — the bot has a different database; the user must re-insert it
// "unknown" — a cache exists but the link carried no revision to check against
function cacheStatus(cached) {
  if (!cached) return "none";
  if (serverRevision.c) return cached.c === serverRevision.c ? "current" : "stale";
  if (serverRevision.t && cached.t) return cached.t === serverRevision.t ? "current" : "stale";
  return "unknown";
}

function renderCacheBar() {
  const cached = readCache();
  const status = cacheStatus(cached);
  if (status === "none") {
    cacheBar.hidden = true;
    cacheRefresh.hidden = true;
    preferredBlob = "";
    return;
  }

  cacheBar.classList.toggle("stale", status === "stale");
  cacheBar.hidden = false;

  // "Refresh" asks the bot for the latest vault: sendData() closes the Mini App
  // and the bot replies in the chat with the current version (and a keyboard
  // URL carrying its revision). Only keyboard-button launches can send.
  cacheRefresh.hidden = !canSendData();

  if (status === "current") {
    preferredBlob = cached.blob;
    const ts = fmtStamp(serverRevision.t || cached.t || cached.savedAt);
    cacheText.innerHTML = "Cached" + (ts ? " " + escapeHtml(ts) : "") +
      ', <span class="cache-verified">verified</span>';
  } else if (status === "stale") {
    preferredBlob = "";
    cacheText.innerHTML = "Cached " + escapeHtml(fmtStamp(cached.t || cached.savedAt)) +
      ', <span class="cache-unverified">outdated</span>';
    pasteField.hidden = false;
    pasteArea.setAttribute("placeholder", "Paste the vault file content (VLT3:...)");
  } else {
    preferredBlob = cached.blob;
    cacheText.innerHTML = 'Cached, <span class="cache-unverified">unverified</span>';
  }
}

function initCache() {
  serverRevision = readUrlRevision();
  renderCacheBar();
}

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

// --- Unlock ---
// A record is { id, cipher, n, u, o, l, e, p }: `id` is the content hash the bot
// stores the row under, `cipher` is the encrypted r1. field and the rest is the
// decrypted plaintext (n is mandatory).
function buildIndex(records) {
  state.records = (records || []).map((r) => {
    const rec = {
      id: r.id,
      cipher: r.cipher,
      n: r.n || "",
      u: r.u || "",
      o: r.o || "",
      l: r.l || "",
      e: r.e || "",
      p: r.p || "",
    };
    recomputeRec(rec);
    return rec;
  });
  state.records.sort((a, b) => a.lowerN.localeCompare(b.lowerN));
}

// Keep the denormalised search fields in sync after an edit.
function recomputeRec(rec) {
  rec.lowerN = (rec.n || "").toLowerCase();
  rec.lowerU = (rec.u || "").toLowerCase();
  rec.lowerO = (rec.o || "").toLowerCase();
  rec.lowerL = (rec.l || "").toLowerCase();
  rec.lowerE = (rec.e || "").toLowerCase();
  rec.first = firstLetter(rec.n);
}

// Plain fields of a record - the canonical form that is hashed and encrypted.
function plainRecord(rec) {
  return { n: rec.n, u: rec.u, o: rec.o, l: rec.l, e: rec.e, p: rec.p };
}

function updateVaultMeta() {
  const count = state.records.length;
  vaultMetaEl.textContent = count + " record" + (count === 1 ? "" : "s");
}

function enterMainScreen(records) {
  buildIndex(records);
  state.query = "";
  state.letter = null;
  searchInput.value = "";
  updateVaultMeta();
  lockScreen.hidden = true;
  mainScreen.hidden = false;
  render();
  searchInput.focus();
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
    state.key = await window.CryptoCore.deriveKey(state.password, state.salt, state.kdf);
  }
  return state.key;
}

function openRecord(rec) {
  state.selected = rec.id;
  state.editing = false;
  state.editingId = null;
  detailsTitle.textContent = "Record details";
  detailsEditBtn.hidden = false;
  detailsDeleteBtn.hidden = false;
  detailsBody.hidden = false;
  editForm.hidden = true;
  saveScreen.hidden = true;

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

  detailsData = { login: rec.l || "", email: rec.e || "", password: rec.p || "" };
  passwordRevealed = false;
  revealPasswordBtn.textContent = "Show";
  detailsPassword.textContent = maskPassword(detailsData.password);
  detailsStatus.hidden = true;

  mainScreen.hidden = true;
  detailsScreen.hidden = false;
}

function maskPassword(secret) {
  return secret ? "•".repeat(Math.max(8, secret.length)) : "—";
}

function closeDetails() {
  detailsScreen.hidden = true;
  mainScreen.hidden = false;
  state.selected = null;
  state.editing = false;
  state.editingId = null;
  editForm.hidden = true;
  detailsBody.hidden = false;
  detailsDeleteBtn.hidden = false;
  saveScreen.hidden = true;
  passwordRevealed = false;
  detailsData = { login: "", email: "", password: "" };
  detailsStatus.hidden = true;
}

// --- Create / update records ---
function setEditError(message) {
  if (!message) {
    editError.hidden = true;
    editError.textContent = "";
    return;
  }
  editError.hidden = false;
  editError.textContent = message;
}

function setEditBusy(busy) {
  editSaveBtn.disabled = busy;
  editCancel.disabled = busy;
}

async function openEditor(rec) {
  state.editing = true;
  state.editingId = rec ? rec.id : null;
  state.selected = rec ? rec.id : null;

  detailsTitle.textContent = rec ? "Edit record" : "New record";
  detailsEditBtn.hidden = true;
  detailsDeleteBtn.hidden = true;
  detailsBody.hidden = true;
  editForm.hidden = false;
  saveScreen.hidden = true;
  setEditError("");

  editName.value = rec ? rec.n : "";
  editLogin.value = rec ? rec.l : "";
  editEmail.value = rec ? rec.e : "";
  editUrl.value = rec ? rec.u : "";
  editNotes.value = rec ? rec.o : "";
  editPassword.value = rec ? rec.p : "";
  editPassword.type = "password";
  editRevealBtn.textContent = "Show";

  mainScreen.hidden = true;
  detailsScreen.hidden = false;
  editName.focus();
}

function cancelEditor() {
  const wasNew = state.editingId === null;
  state.editing = false;
  state.editingId = null;
  editForm.hidden = true;
  detailsBody.hidden = false;
  detailsEditBtn.hidden = false;
  detailsDeleteBtn.hidden = false;
  detailsTitle.textContent = "Record details";
  setEditError("");
  if (wasNew) closeDetails();
}

async function saveEditor(e) {
  e.preventDefault();
  if (editSaveBtn.disabled) return;

  const n = editName.value.trim();
  const password = editPassword.value;
  if (!n) { setEditError("Title is required."); return; }
  if (!password) { setEditError("Password is required."); return; }

  setEditBusy(true);
  setEditError("");
  try {
    const key = await getCredentialKey();
    const rec = plainRecord({
      n: n,
      u: editUrl.value.trim(),
      o: editNotes.value,
      l: editLogin.value.trim(),
      e: editEmail.value.trim(),
      p: password,
    });

    // The id is the hash of the canonical record: an edit is a delete of the old
    // id plus an add of the new one, both in this single message.
    const newId = await window.CryptoCore.recordId(rec);
    const cipher = await window.CryptoCore.encryptRecord(key, rec);

    // "Add" that matches an existing record's content is really an update: the
    // two collapse into the same id (and the bot stores one row per id).
    const existing = state.records.find((r) => r.id === newId);
    const previous = state.editingId != null
      ? state.records.find((r) => r.id === state.editingId)
      : (existing || null);
    const ops = [];
    if (previous && previous.id !== newId) ops.push({ del: true, id: previous.id });
    ops.push({ id: newId, cipher: cipher });

    const note = (previous ? "Updated record: " : "Added record: ") + n;
    const payload = window.CryptoCore.buildOpPayload(state.headerB64, ops, note);
    if (payload.length > MAX_PAYLOAD) {
      setEditError("This record is too large to send in one message — shorten the notes.");
      return;
    }

    if (previous) {
      previous.id = newId;
      previous.cipher = cipher;
      previous.n = rec.n;
      previous.u = rec.u;
      previous.o = rec.o;
      previous.l = rec.l;
      previous.e = rec.e;
      previous.p = rec.p;
      recomputeRec(previous);
    } else {
      const created = Object.assign({ id: newId, cipher: cipher }, rec);
      recomputeRec(created);
      state.records.push(created);
    }

    const target = previous || state.records[state.records.length - 1];
    endEditing();
    await pushChange(ops, payload, target);
  } catch (err) {
    setEditError("Could not save: " + (err && err.message ? err.message : err));
  } finally {
    setEditBusy(false);
  }
}

/** Leave the edit form and show the record's details again. */
function endEditing() {
  state.editing = false;
  state.editingId = null;
  editForm.hidden = true;
  detailsBody.hidden = false;
  detailsEditBtn.hidden = false;
  detailsDeleteBtn.hidden = false;
  detailsTitle.textContent = "Record details";
}

function deleteSelected() {
  const rec = state.records.find((r) => r.id === state.selected);
  if (!rec) return;
  confirmDialog("Delete \u201C" + rec.n + "\u201D?").then(async (ok) => {
    if (!ok) return;
    state.records = state.records.filter((r) => r.id !== rec.id);
    const note = "Deleted record: " + rec.n;
    const ops = [{ del: true, id: rec.id }];
    const payload = window.CryptoCore.buildOpPayload(state.headerB64, ops, note);
    closeDetails();
    await pushChange(ops, payload, null);
  });
}

/** Ask the user to confirm; prefer Telegram's native dialog when available. */
function confirmDialog(message) {
  return new Promise((resolve) => {
    if (tg && typeof tg.showConfirm === "function") {
      try {
        tg.showConfirm(message, (ok) => resolve(!!ok));
        return;
      } catch (e) {
        // fall through to window.confirm
      }
    }
    resolve(window.confirm(message));
  });
}

/**
 * Rebuild the container from the in-memory records, cache it as the local
 * revision, then hand the small update payload to the bot. `target` (optional)
 * is the record to re-open in the details view afterwards.
 */
async function pushChange(ops, payload, target) {
  const stored = state.records.map((r) => ({ i: r.id, d: r.cipher }));
  const container = await window.CryptoCore.buildVault(state.headerB64, stored);

  serverRevision = { c: window.CryptoCore.checksumOf(container), v: "", t: "" };
  writeCache(container);
  preferredBlob = container;

  state.records.sort((a, b) => a.lowerN.localeCompare(b.lowerN));
  updateVaultMeta();
  render();
  if (target) openRecord(target);
  showSavePanel(payload);
}

// Telegram.WebApp.sendData() is only delivered when the Mini App was launched
// from a reply-keyboard button (those launches carry an empty initData and no
// query_id); inline-button, menu-button and browser launches cannot send.
function canSendData() {
  return hasSendData()
    && tg.platform && tg.platform !== "unknown"
    && !(tg.initData && tg.initData.length)
    && !(tg.initDataUnsafe && tg.initDataUnsafe.query_id);
}

/** The SDK exposes sendData() at all (true even where it cannot be delivered). */
function hasSendData() {
  return !!(tg && typeof tg.sendData === "function");
}

function sendToBot(cmd) {
  try {
    tg.sendData(cmd); // service message the bot stores; closes the Mini App
    return true;
  } catch (e) {
    return false;
  }
}

function renderSavePanel(cmd) {
  const canAuto = canSendData();
  saveCommand.value = cmd;
  saveSend.hidden = !canAuto;
  saveCopy.classList.toggle("button-secondary", canAuto);
  saveCopy.textContent = "Copy command";
  saveHint.textContent = canAuto
    ? "Tap \u201CSend to bot\u201D to store this change, or copy it and paste it into the chat."
    : "Saved in this browser \u2014 not stored on the bot yet. Telegram only delivers the change when the Mini App is opened from the keyboard button in the chat, so tap \u201CCopy command\u201D and paste it there, or reopen the vault from that keyboard button to send it automatically.";
  saveScreen.hidden = false;
  copyText(cmd).then(() => {
    saveCopy.textContent = "Copied!";
    setTimeout(() => { saveCopy.textContent = "Copy command"; }, 1500);
  }).catch(() => {});
}

// The bot's reply carries the change note, and the payload is exactly what the
// bot expects - the optional "note:" line is already part of it.
function showSavePanel(payload) {
  if (canSendData() && sendToBot(payload)) {
    clearPending();
    // sendData closes the Mini App. If the client ignored it, fall back to the
    // manual panel a moment later.
    setTimeout(() => {
      if (saveScreen.hidden) renderSavePanel(payload);
    }, 1000);
    return;
  }
  setPending(payload);
  renderSavePanel(payload);
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

// --- Passphrase strength meter ---
// Heuristic only: a rough entropy estimate with penalties for obvious
// patterns, so the user gets feedback while typing. Never blocks unlocking.
function scorePassphrase(pw) {
  const p = String(pw || "");
  if (!p) return { score: 0, label: "" };

  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^A-Za-z0-9]/.test(p)) pool += 33;

  let bits = pool > 0 ? Math.log2(pool) * p.length : 0;

  if (/^(.)\1*$/.test(p)) bits = Math.min(bits, 10);        // one repeated char
  if (/(.)\1{2,}/.test(p)) bits -= 10;                        // runs like "aaa"
  if (/^\d+$/.test(p)) bits -= 10;                           // digits only
  if (/(012|123|234|345|456|567|678|789|890)/.test(p)) bits -= 10;
  if (/(abc|bcd|cde|def|qwe|asd|zxc|pass|admin|letmein|welcome|qwerty|dragon)/i.test(p)) bits -= 15;
  if (bits < 0) bits = 0;

  let score;
  if (bits < 28) score = 0;
  else if (bits < 40) score = 1;
  else if (bits < 60) score = 2;
  else if (bits < 80) score = 3;
  else score = 4;

  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  return { score, label: labels[score] };
}

function updateStrength() {
  const pw = passwordInput.value;
  if (!pw) {
    strengthEl.hidden = true;
    return;
  }
  const { score, label } = scorePassphrase(pw);
  strengthEl.hidden = false;
  strengthEl.dataset.score = String(score);
  strengthFill.style.width = ((score + 1) / 5 * 100) + "%";
  strengthLabel.textContent = "Strength: " + label;
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

    // Candidate sources. A non-empty database-string box is authoritative — if
    // it fails, we do NOT fall back. Otherwise try the cached copy, then the
    // clipboard buffer.
    const candidates = [];
    const pasted = pasteArea.value.trim();
    if (pasted) {
      candidates.push(pasted);
    } else {
      if (preferredBlob) candidates.push(preferredBlob);
      if (navigator.clipboard && navigator.clipboard.readText) {
        try {
          const clip = (await navigator.clipboard.readText()).trim();
          if (clip && !candidates.includes(clip)) candidates.push(clip);
        } catch (e) {
          // clipboard unavailable — nothing to add
        }
      }
    }

    if (!candidates.length) {
      showResult("No database string found — paste it below.", true);
      showPasteFallback();
      return;
    }

    showResult("Decrypting…");
    let lastError = null;
    for (const containerText of candidates) {
      try {
        const vault = await window.CryptoCore.openVault(containerText, password);
        result.hidden = true;
        writeCache(containerText);
        state.password = password;
        state.headerB64 = vault.headerB64;
        state.salt = vault.salt;
        state.kdf = vault.kdf;
        state.key = null;
        enterMainScreen(vault.records);
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
passwordInput.addEventListener("input", updateStrength);

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

detailsBack.addEventListener("click", () => {
  if (state.editing) cancelEditor();
  else closeDetails();
});

detailsEditBtn.addEventListener("click", () => {
  const rec = state.records.find((r) => r.id === state.selected);
  if (rec) openEditor(rec);
});

detailsDeleteBtn.addEventListener("click", deleteSelected);

addBtn.addEventListener("click", () => openEditor(null));

editForm.addEventListener("submit", saveEditor);
editCancel.addEventListener("click", cancelEditor);

editRevealBtn.addEventListener("click", () => {
  const show = editPassword.type === "password";
  editPassword.type = show ? "text" : "password";
  editRevealBtn.textContent = show ? "Hide" : "Show";
});

saveBack.addEventListener("click", () => {
  saveScreen.hidden = true;
});

saveCopy.addEventListener("click", async () => {
  clearPending(); // taking the manual route — don't auto-send later
  await copyText(saveCommand.value);
  saveCopy.textContent = "Copied!";
  setTimeout(() => { saveCopy.textContent = "Copy command"; }, 1500);
});

saveSend.addEventListener("click", () => {
  if (!canSendData()) return;
  try {
    tg.sendData(saveCommand.value);
  } catch (e) {
    saveHint.textContent = "This client refused the automatic send \u2014 copy the command and paste it into the chat instead.";
    return;
  }
  clearPending();
  saveSend.textContent = "Sent!";
  // sendData closes the Mini App. If it is still open a moment later the client
  // almost certainly ignored it (e.g. inline/menu-button launch).
  setTimeout(() => {
    saveSend.textContent = "Send to bot";
    if (document.visibilityState === "visible") {
      saveHint.textContent = "The client didn\u2019t hand the update to the bot. Open the vault from the keyboard button in the chat, or copy the command and paste it into the chat.";
    }
  }, 1200);
});

revealPasswordBtn.addEventListener("click", () => {
  passwordRevealed = !passwordRevealed;
  revealPasswordBtn.textContent = passwordRevealed ? "Hide" : "Show";
  detailsPassword.textContent = passwordRevealed
    ? (detailsData.password || "—")
    : maskPassword(detailsData.password);
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

// --- Theme switcher ---
const THEME_KEY = "botwheel-theme";
const themeButtons = document.querySelectorAll(".theme-btn");

function applyTheme(name) {
  document.documentElement.setAttribute("data-theme", name);
  try {
    localStorage.setItem(THEME_KEY, name);
  } catch (e) {
    // storage unavailable — theme applies for this session only
  }
  themeButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.themeValue === name);
  });
}

(function initTheme() {
  let saved = "default";
  try {
    saved = localStorage.getItem(THEME_KEY) || "default";
  } catch (e) {}
  applyTheme(saved);
})();

themeButtons.forEach((btn) => {
  btn.addEventListener("click", () => applyTheme(btn.dataset.themeValue));
});

// --- Cache controls ---
// "Refresh" hands the bot a /refresh over sendData(): the Mini App closes and
// the bot replies in the chat with the current vault (plus a keyboard whose URL
// carries its revision). Only keyboard-button launches can send; elsewhere it
// is hidden.
cacheRefresh.addEventListener("click", () => {
  if (!canSendData()) return;
  try {
    tg.sendData("/refresh");
  } catch (e) {
    showResult("This client refused the automatic send — tap “Refresh database” in the chat instead.", true);
    return;
  }
  // If the app is still visible a moment later the client almost certainly
  // ignored the send (e.g. an inline/menu/direct-link launch).
  setTimeout(() => {
    if (document.visibilityState === "visible") {
      showResult("The client didn’t deliver the command — tap “Refresh database” in the chat instead.", true);
    }
  }, 1200);
});

initCache();
flushPending();
