/*
 * crypto-core.js — CLIENT-SIDE CRYPTO (browser)
 * =============================================
 * Encryption primitives used by the Mini App (app.js), which runs in the
 * browser / Telegram webview.
 *
 * Uses only web-platform APIs:
 *   - WebCrypto (crypto.subtle)
 *   - CompressionStream / DecompressionStream (gzip)
 *   - TextEncoder / TextDecoder
 *
 * Loading:
 *   - Browser: <script src="crypto-core.js"></script> → exposes window.CryptoCore
 *
 * Formats:
 *   Record (one row):    "r1.<base64url(iv || ct || tag)>"
 *                        plaintext = canonical JSON {n,u,o,l,e,p}
 *   Vault header:        base64url( kdfHeader(13) || salt(16) )   (the "key spec")
 *   Vault (container):   "VLT3:<base64url(header || gzip(recordsJson))>.<8-hex>"
 *                        recordsJson = [{"i":"<recordId>","d":"r1.…"}, …]
 *   Update payload:      "VUP1:<headerB64>\nadd:<id>:<r1.…>\ndel:<id>\nnote: …"
 *
 * The database is a set of independently encrypted records; the container is
 * just the header plus those opaque records (no whole-vault encryption), so the
 * server can assemble it from its rows without ever seeing the password.
 *
 * The 13-byte KDF header (little-endian) self-describes the key derivation:
 *   id(1) || p1(4) || p2(4) || p3(4)
 *   kdf "argon2id": p1 = memory KiB, p2 = iterations, p3 = parallelism
 *   kdf "pbkdf2"  : p1 = iterations (p2/p3 unused)
 *
 * The 8-hex suffix is the content revision of the record set (sorted
 * "id:cipher" pairs) - the same value the bot stamps into the Mini App URL as
 * "?c=" and the Mini App caches, so a stale copy is detected without comparing
 * whole blobs.
 */

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Constants
  // -------------------------------------------------------------------------

  var DEFAULT_ITERATIONS = 600000; // PBKDF2-SHA256 rounds (legacy)
  var SALT_BYTES = 16;             // PBKDF2/Argon2 salt
  var IV_BYTES = 12;               // AES-GCM nonce (96-bit)

  // KDF identifiers + defaults for the self-describing vault header.
  var KDF_PBKDF2 = 1;
  var KDF_ARGON2ID = 2;
  var HEADER_BYTES = 13;           // id(1) || p1(4) || p2(4) || p3(4)
  var HEADER_SALT_BYTES = HEADER_BYTES + SALT_BYTES; // 29 - the vault key spec
  var DEFAULT_ARGON2 = { memoryKiB: 65536, iterations: 3, parallelism: 1 };

  // Record + container formats.
  var RECORD_PREFIX = 'r1.';       // one encrypted record
  var RECORD_ID_HEX = 16;          // chars taken from the record-id hash
  var VAULT_PREFIX = 'VLT3:';      // the whole database as one pasteable string
  // Vendored Argon2 WASM (hash-wasm, MIT); loaded lazily on first use.
  var ARGON2_SCRIPT = 'vendor/argon2.umd.min.js';

  var encoder = new TextEncoder();
  var decoder = new TextDecoder();

  // -------------------------------------------------------------------------
  // base64url (portable, no btoa/Buffer needed)
  // -------------------------------------------------------------------------

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  function toBase64url(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 3) {
      var b0 = bytes[i];
      var b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
      var b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
      var n = (b0 << 16) | (b1 << 8) | b2;
      out += B64[(n >> 18) & 63];
      out += B64[(n >> 12) & 63];
      out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : '';
      out += i + 2 < bytes.length ? B64[n & 63] : '';
    }
    return out;
  }

  function fromBase64url(str) {
    var clean = String(str).replace(/=+$/, '');
    var out = [];
    var buf = 0;
    var bits = 0;
    for (var i = 0; i < clean.length; i++) {
      var idx = B64.indexOf(clean[i]);
      if (idx === -1) throw new Error('Invalid base64url character: ' + clean[i]);
      buf = (buf << 6) | idx;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.push((buf >> bits) & 0xff);
      }
    }
    return new Uint8Array(out);
  }

  // -------------------------------------------------------------------------
  // Small byte helpers
  // -------------------------------------------------------------------------

  function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  function concatBytes() {
    var len = 0;
    for (var i = 0; i < arguments.length; i++) len += arguments[i].length;
    var out = new Uint8Array(len);
    var off = 0;
    for (var j = 0; j < arguments.length; j++) {
      out.set(arguments[j], off);
      off += arguments[j].length;
    }
    return out;
  }

  async function sha256Hex(str) {
    var digest = await crypto.subtle.digest('SHA-256', encoder.encode(str));
    var bytes = new Uint8Array(digest);
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
  }

  // -------------------------------------------------------------------------
  // Key derivation + AES-GCM
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // Key derivation: Argon2id (memory-hard, default) or PBKDF2 (legacy)
  // -------------------------------------------------------------------------

  /**
   * Normalise a KDF spec. Accepts:
   *   undefined/null -> Argon2id with DEFAULT_ARGON2
   *   a number       -> PBKDF2 with that many iterations
   *   { id:'pbkdf2', iterations }
   *   { id:'argon2id', memoryKiB, iterations, parallelism }
   */
  function normalizeKdf(params) {
    if (params == null) {
      return {
        id: 'argon2id',
        memoryKiB: DEFAULT_ARGON2.memoryKiB,
        iterations: DEFAULT_ARGON2.iterations,
        parallelism: DEFAULT_ARGON2.parallelism,
      };
    }
    if (typeof params === 'number') {
      return { id: 'pbkdf2', iterations: params };
    }
    if (params.id === 'pbkdf2') {
      return { id: 'pbkdf2', iterations: params.iterations || DEFAULT_ITERATIONS };
    }
    if (params.id === 'argon2id' || params.memoryKiB) {
      return {
        id: 'argon2id',
        memoryKiB: params.memoryKiB || DEFAULT_ARGON2.memoryKiB,
        iterations: params.iterations || DEFAULT_ARGON2.iterations,
        parallelism: params.parallelism || DEFAULT_ARGON2.parallelism,
      };
    }
    return { id: 'pbkdf2', iterations: params.iterations || DEFAULT_ITERATIONS };
  }

  var argon2Library = null;

  /** Lazily load the vendored Argon2 WASM library (only when first needed). */
  function ensureArgon2() {
    if (global.hashwasm && global.hashwasm.argon2id) {
      return Promise.resolve(global.hashwasm);
    }
    if (argon2Library) {
      return argon2Library;
    }
    argon2Library = new Promise(function (resolve, reject) {
      var script = document.createElement('script');
      script.src = ARGON2_SCRIPT;
      script.onload = function () {
        if (global.hashwasm && global.hashwasm.argon2id) {
          resolve(global.hashwasm);
        } else {
          argon2Library = null;
          reject(new Error('argon2: ' + ARGON2_SCRIPT + ' loaded but hashwasm.argon2id is missing'));
        }
      };
      script.onerror = function () {
        argon2Library = null;
        reject(new Error('argon2: could not load ' + ARGON2_SCRIPT));
      };
      document.head.appendChild(script);
    });
    return argon2Library;
  }

  /** PBKDF2-SHA256 -> AES-256 CryptoKey (legacy path). */
  async function deriveKeyPbkdf2(password, salt, iterations) {
    var rounds = iterations || DEFAULT_ITERATIONS;
    var base = await crypto.subtle.importKey(
      'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: rounds, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /** Argon2id (WASM) -> AES-256 CryptoKey. */
  async function deriveKeyArgon2(password, salt, p) {
    var hw = await ensureArgon2();
    var raw = await hw.argon2id({
      password: password,
      salt: salt,
      parallelism: p.parallelism,
      iterations: p.iterations,
      memorySize: p.memoryKiB,
      hashLength: 32,
      outputType: 'binary',
    });
    if (!(raw instanceof Uint8Array)) {
      raw = new Uint8Array(raw);
    }
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  /**
   * Derive a 256-bit AES-GCM CryptoKey from a password + salt.
   * See {@link normalizeKdf} for the accepted parameter shapes.
   */
  async function deriveKey(password, salt, params) {
    var p = normalizeKdf(params);
    if (p.id === 'argon2id') {
      return deriveKeyArgon2(password, salt, p);
    }
    return deriveKeyPbkdf2(password, salt, p.iterations);
  }

  // --- Self-describing KDF header, 13 bytes, little-endian ---

  function writeU32(buf, off, val) {
    buf[off] = val & 0xff;
    buf[off + 1] = (val >>> 8) & 0xff;
    buf[off + 2] = (val >>> 16) & 0xff;
    buf[off + 3] = (val >>> 24) & 0xff;
  }

  function readU32(buf, off) {
    return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
  }

  /** id(1) || p1(4) || p2(4) || p3(4); semantics depend on the KDF id. */
  function encodeKdfHeader(p) {
    var b = new Uint8Array(HEADER_BYTES);
    if (p.id === 'argon2id') {
      b[0] = KDF_ARGON2ID;
      writeU32(b, 1, p.memoryKiB);
      writeU32(b, 5, p.iterations);
      writeU32(b, 9, p.parallelism);
    } else {
      b[0] = KDF_PBKDF2;
      writeU32(b, 1, p.iterations);
    }
    return b;
  }

  function decodeKdfHeader(b) {
    var id = b[0];
    if (id === KDF_ARGON2ID) {
      return { id: 'argon2id', memoryKiB: readU32(b, 1), iterations: readU32(b, 5), parallelism: readU32(b, 9) };
    }
    if (id === KDF_PBKDF2) {
      return { id: 'pbkdf2', iterations: readU32(b, 1) };
    }
    throw new Error('decodeKdfHeader: unknown KDF id ' + id);
  }

  /** AES-256-GCM encrypt. Returns Uint8Array(iv || ciphertext || tag). */
  async function aesEncrypt(key, bytes) {
    var iv = randomBytes(IV_BYTES);
    var ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, bytes)
    );
    return concatBytes(iv, ct);
  }

  /** AES-256-GCM decrypt. `blob` is Uint8Array(iv || ciphertext || tag). */
  async function aesDecrypt(key, blob) {
    var iv = blob.subarray(0, IV_BYTES);
    var ct = blob.subarray(IV_BYTES);
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct)
    );
  }

  // -------------------------------------------------------------------------
  // gzip (via CompressionStream)
  // -------------------------------------------------------------------------

  async function gzip(bytes) {
    var stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function gunzip(bytes) {
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  // -------------------------------------------------------------------------
  // Records (one independently encrypted database row)
  // -------------------------------------------------------------------------

  function jsonString(s) {
    return JSON.stringify(s == null ? '' : String(s));
  }

  /**
   * Canonical JSON of a record - fixed key order, no stray whitespace. Both the
   * record id and the ciphertext are derived from this exact string, so the same
   * record always hashes to the same id (identical records collapse into one).
   */
  function canonicalRecord(rec) {
    return '{"n":' + jsonString(rec.n)
      + ',"u":' + jsonString(rec.u)
      + ',"o":' + jsonString(rec.o)
      + ',"l":' + jsonString(rec.l)
      + ',"e":' + jsonString(rec.e)
      + ',"p":' + jsonString(rec.p) + '}';
  }

  /** Content hash of a record: the row key the bot stores it under. */
  async function recordId(rec) {
    return (await sha256Hex(canonicalRecord(rec))).slice(0, RECORD_ID_HEX);
  }

  /** Encrypt one record with the vault key -> "r1.<base64url(iv||ct||tag)>". */
  async function encryptRecord(key, rec) {
    var enc = await aesEncrypt(key, encoder.encode(canonicalRecord(rec)));
    return RECORD_PREFIX + toBase64url(enc);
  }

  /** Reverse of encryptRecord -> { n, u, o, l, e, p }. */
  async function decryptRecord(key, cipher) {
    if (typeof cipher !== 'string' || cipher.slice(0, 3) !== RECORD_PREFIX) {
      throw new Error('decryptRecord: bad record format');
    }
    var enc = fromBase64url(cipher.slice(RECORD_PREFIX.length));
    var rec = JSON.parse(decoder.decode(await aesDecrypt(key, enc)));
    return {
      n: rec.n || '', u: rec.u || '', o: rec.o || '',
      l: rec.l || '', e: rec.e || '', p: rec.p || '',
    };
  }

  // -------------------------------------------------------------------------
  // Vault header (KDF params + salt) shared by every record
  // -------------------------------------------------------------------------

  /** base64url(kdfHeader(13) || salt(16)) - what every record key derives from. */
  function encodeVaultHeader(kdf, salt) {
    return toBase64url(concatBytes(encodeKdfHeader(kdf), salt));
  }

  function decodeVaultHeader(b64) {
    var raw = fromBase64url(b64);
    if (raw.length !== HEADER_SALT_BYTES) {
      throw new Error('vault header: expected ' + HEADER_SALT_BYTES
        + ' bytes, got ' + raw.length);
    }
    return {
      kdf: decodeKdfHeader(raw.subarray(0, HEADER_BYTES)),
      salt: raw.subarray(HEADER_BYTES),
    };
  }

  /** A fresh vault header (Argon2id defaults + a new salt). */
  function newVaultHeader() {
    return encodeVaultHeader(DEFAULT_ARGON2, randomBytes(SALT_BYTES));
  }

  // -------------------------------------------------------------------------
  // The container: the whole database as one pasteable string
  // -------------------------------------------------------------------------

  function byId(a, b) {
    return a.i < b.i ? -1 : a.i > b.i ? 1 : 0;
  }

  /**
   * Content revision of a record set (sorted "id:cipher" pairs) - the 8-hex
   * suffix of the container and the "?c=" stamp the bot hands to the Mini App.
   * records: [{ i, d }, …]
   */
  async function revisionOf(records) {
    var sorted = records.slice().sort(byId);
    var text = '';
    for (var i = 0; i < sorted.length; i++) {
      text += sorted[i].i + ':' + sorted[i].d + '\n';
    }
    return (await sha256Hex(text)).slice(0, 8);
  }

  function recordsJson(records) {
    var sorted = records.slice().sort(byId);
    var out = '[';
    for (var i = 0; i < sorted.length; i++) {
      if (i > 0) out += ',';
      out += '{"i":' + jsonString(sorted[i].i) + ',"d":' + jsonString(sorted[i].d) + '}';
    }
    return out + ']';
  }

  /**
   * Assemble the container the user pastes into the Mini App (and the bot sends
   * in a .txt file): "VLT3:<base64url(header || gzip(records))>.<8hex>".
   * records: [{ i, d }, …]
   */
  async function buildVault(headerB64, records) {
    var gz = await gzip(encoder.encode(recordsJson(records)));
    var body = toBase64url(concatBytes(fromBase64url(headerB64), gz));
    return VAULT_PREFIX + body + '.' + (await revisionOf(records));
  }

  /**
   * Pull the container ("VLT3:…") out of a possibly larger text - the user may
   * copy the whole file content - and drop any trailing text. "" when absent.
   */
  function extractTransport(str) {
    var s = String(str == null ? '' : str).trim();
    var at = s.indexOf(VAULT_PREFIX);
    if (at < 0) {
      return '';
    }
    s = s.slice(at);
    for (var i = 0; i < s.length; i++) {
      if (/\s/.test(s.charAt(i))) {
        s = s.slice(0, i);
        break;
      }
    }
    return s;
  }

  /** Split a container into its header + opaque rows. No password needed. */
  function parseVaultStructure(str) {
    var payload = extractTransport(str);
    if (!payload) {
      throw new Error('openVault: not a vault string (expected "VLT3:…")');
    }
    var body = payload.slice(VAULT_PREFIX.length);
    var dot = body.lastIndexOf('.');
    if (dot < 0) {
      throw new Error('openVault: missing checksum');
    }
    var checksum = body.slice(dot + 1);
    body = body.slice(0, dot);
    var raw = fromBase64url(body);
    if (raw.length < HEADER_SALT_BYTES) {
      throw new Error('openVault: truncated container');
    }
    return {
      headerB64: toBase64url(raw.subarray(0, HEADER_SALT_BYTES)),
      checksum: checksum,
      gz: raw.subarray(HEADER_SALT_BYTES),
    };
  }

  /**
   * Decrypt the whole container -> { headerB64, kdf, salt, checksum, records }.
   * records: [{ id, cipher, n, u, o, l, e, p }, …]. Throws on a wrong password
   * (AES-GCM tag) or a damaged / mismatched copy.
   */
  async function openVault(str, password) {
    var parts = parseVaultStructure(str);
    var json = decoder.decode(await gunzip(parts.gz));
    var list = JSON.parse(json);

    var expected = await revisionOf(list);
    if (parts.checksum !== expected) {
      throw new Error('openVault: revision mismatch (damaged copy?)');
    }

    var header = decodeVaultHeader(parts.headerB64);
    var key = await deriveKey(password, header.salt, header.kdf);

    var records = [];
    for (var i = 0; i < list.length; i++) {
      var rec = await decryptRecord(key, list[i].d);
      records.push({
        id: list[i].i, cipher: list[i].d,
        n: rec.n, u: rec.u, o: rec.o, l: rec.l, e: rec.e, p: rec.p,
      });
    }
    return {
      headerB64: parts.headerB64, kdf: header.kdf, salt: header.salt,
      checksum: parts.checksum, records: records,
    };
  }

  // -------------------------------------------------------------------------
  // Update payload (Mini App -> bot): one record change, always < 4096 chars
  // -------------------------------------------------------------------------

  /**
   * "VUP1:<headerB64>", then one op per line, then an optional "note:" line.
   * ops: [{ id, cipher }] adds, or [{ id, del: true }] deletes. An edit is a
   * del + an add in the same message.
   */
  function buildOpPayload(headerB64, ops, note) {
    var out = 'VUP1:' + headerB64;
    for (var i = 0; i < ops.length; i++) {
      var op = ops[i];
      out += '\n' + (op.del ? 'del:' + op.id : 'add:' + op.id + ':' + op.cipher);
    }
    if (note) {
      out += '\nnote: ' + String(note).replace(/\s+/g, ' ').trim();
    }
    return out;
  }

  /** The 8-hex suffix of a container (also the bot's "?c=" revision stamp). */
  function checksumOf(str) {
    var s = String(str || '');
    var dot = s.lastIndexOf('.');
    return dot === -1 ? '' : s.slice(dot + 1);
  }

  // -------------------------------------------------------------------------
  // Export (browser global)
  // -------------------------------------------------------------------------

  var api = {
    DEFAULT_ITERATIONS: DEFAULT_ITERATIONS,
    DEFAULT_ARGON2: DEFAULT_ARGON2,
    KDF_PBKDF2: KDF_PBKDF2,
    KDF_ARGON2ID: KDF_ARGON2ID,
    SALT_BYTES: SALT_BYTES,
    IV_BYTES: IV_BYTES,
    RECORD_PREFIX: RECORD_PREFIX,
    VAULT_PREFIX: VAULT_PREFIX,
    randomBytes: randomBytes,
    toBase64url: toBase64url,
    fromBase64url: fromBase64url,
    sha256Hex: sha256Hex,
    deriveKey: deriveKey,
    canonicalRecord: canonicalRecord,
    recordId: recordId,
    encryptRecord: encryptRecord,
    decryptRecord: decryptRecord,
    encodeVaultHeader: encodeVaultHeader,
    decodeVaultHeader: decodeVaultHeader,
    newVaultHeader: newVaultHeader,
    revisionOf: revisionOf,
    buildVault: buildVault,
    parseVaultStructure: parseVaultStructure,
    openVault: openVault,
    buildOpPayload: buildOpPayload,
    checksumOf: checksumOf,
  };

  global.CryptoCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
