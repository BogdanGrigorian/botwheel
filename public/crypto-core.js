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
 *   Field (self-contained):  "s1.<base64url(salt || iv || ct || tag)>"
 *   Field (with key):        "s1.<base64url(iv || ct || tag)>"
 *   Vault (transport):       "VLT2:<base64url(header || salt || iv || ct || tag)>.<8-hex-checksum>"
 *   Vault (legacy):          "VLT1:<base64url(salt || iv || ct || tag)>.<8-hex-checksum>"
 *
 * The VLT2 header (13 bytes, little-endian) self-describes the KDF so old and
 * new vaults coexist:
 *   id(1) || p1(4) || p2(4) || p3(4)
 *   kdf "argon2id": p1 = memory KiB, p2 = iterations, p3 = parallelism
 *   kdf "pbkdf2"  : p1 = iterations (p2/p3 unused)
 */

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Constants
  // -------------------------------------------------------------------------

  var DEFAULT_ITERATIONS = 600000; // PBKDF2-SHA256 rounds (legacy VLT1)
  var SALT_BYTES = 16;             // PBKDF2/Argon2 salt
  var IV_BYTES = 12;               // AES-GCM nonce (96-bit)

  // KDF identifiers + defaults for the self-describing VLT2 header.
  var KDF_PBKDF2 = 1;
  var KDF_ARGON2ID = 2;
  var HEADER_BYTES = 13;           // id(1) || p1(4) || p2(4) || p3(4)
  var DEFAULT_ARGON2 = { memoryKiB: 65536, iterations: 3, parallelism: 1 };
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
  // Key derivation: Argon2id (memory-hard, default) or PBKDF2 (legacy VLT1)
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

  /** PBKDF2-SHA256 -> AES-256 CryptoKey (legacy VLT1 path). */
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

  // --- Self-describing KDF header (VLT2), 13 bytes, little-endian ---

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
    throw new Error('decryptDatabase: unknown KDF id ' + id);
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
  // Field encryption (single secret string)
  // -------------------------------------------------------------------------

  /**
   * Encrypt a single plaintext string with a password.
   * Self-contained (generates its own salt). Returns "s1.<base64url>".
   */
  async function encryptSecret(plaintext, password, iterations) {
    var salt = randomBytes(SALT_BYTES);
    var key = await deriveKey(password, salt, iterations);
    var enc = await aesEncrypt(key, encoder.encode(plaintext));
    return 's1.' + toBase64url(concatBytes(salt, enc));
  }

  /** Reverse of encryptSecret. Throws on wrong password. */
  async function decryptSecret(encoded, password, iterations) {
    if (typeof encoded !== 'string' || encoded.slice(0, 3) !== 's1.') {
      throw new Error('decryptSecret: bad field format');
    }
    var raw = fromBase64url(encoded.slice(3));
    var salt = raw.subarray(0, SALT_BYTES);
    var enc = raw.subarray(SALT_BYTES);
    var key = await deriveKey(password, salt, iterations);
    return decoder.decode(await aesDecrypt(key, enc));
  }

  /**
   * Bulk variants: encrypt/decrypt with an ALREADY-derived key
   * (no salt inside — the key already implies it). Use these for many
   * records so PBKDF2 runs once per vault instead of once per record.
   */
  async function encryptWithKey(key, plaintext) {
    var enc = await aesEncrypt(key, encoder.encode(plaintext));
    return 's1.' + toBase64url(enc);
  }

  async function decryptWithKey(key, encoded) {
    var enc = fromBase64url(encoded.slice(3));
    return decoder.decode(await aesDecrypt(key, enc));
  }

  // -------------------------------------------------------------------------
  // Whole-database (vault) encryption
  // -------------------------------------------------------------------------

  /**
   * Encrypt the whole (plain) database into one transport string.
   * Pipeline: JSON -> gzip -> AES-256-GCM -> base64url -> "VLT2:<body>.<checksum>".
   * opts: { salt?: Uint8Array, kdf?: number|object }  (see normalizeKdf)
   */
  async function encryptDatabase(entries, password, opts) {
    opts = opts || {};
    var kdf = normalizeKdf(opts.kdf);
    var salt = opts.salt || randomBytes(SALT_BYTES);
    var key = await deriveKey(password, salt, kdf);

    var json = encoder.encode(JSON.stringify({ version: 3, entries: entries }));
    var gz = await gzip(json);
    var enc = await aesEncrypt(key, gz);

    var header = encodeKdfHeader(kdf);
    var body = toBase64url(concatBytes(header, salt, enc));
    var checksum = (await sha256Hex(body)).slice(0, 8);

    return 'VLT2:' + body + '.' + checksum;
  }

  /**
   * Pull the transport string ("VLT2:…"/"VLT1:…") out of a possibly larger
   * text — the user may copy the whole chat message, not just the blob — and
   * drop any trailing text. Returns "" when there is no transport string.
   */
  function extractTransport(str) {
    var s = String(str == null ? '' : str).trim();
    var at = s.indexOf('VLT2:');
    if (at < 0) {
      at = s.indexOf('VLT1:');
    }
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

  /**
   * Decrypt a transport string back into { salt, kdf, version, entries }.
   * Accepts VLT2 (self-describing) and legacy VLT1 (PBKDF2 600k).
   * Throws on wrong password (GCM auth failure) or damaged copy (checksum).
   */
  async function decryptDatabase(str, password) {
    var payload = extractTransport(str);
    if (!payload) {
      throw new Error('decryptDatabase: bad vault format');
    }
    var tag = payload.slice(0, 5);
    payload = payload.slice(5);
    var dot = payload.lastIndexOf('.');
    var body = payload.slice(0, dot);
    var checksum = payload.slice(dot + 1);

    var expected = (await sha256Hex(body)).slice(0, 8);
    if (checksum !== expected) {
      throw new Error('decryptDatabase: checksum mismatch (damaged copy?)');
    }

    var raw = fromBase64url(body);
    var kdf, salt, enc;
    if (tag === 'VLT2:') {
      kdf = decodeKdfHeader(raw.subarray(0, HEADER_BYTES));
      salt = raw.subarray(HEADER_BYTES, HEADER_BYTES + SALT_BYTES);
      enc = raw.subarray(HEADER_BYTES + SALT_BYTES);
    } else {
      kdf = { id: 'pbkdf2', iterations: DEFAULT_ITERATIONS };
      salt = raw.subarray(0, SALT_BYTES);
      enc = raw.subarray(SALT_BYTES);
    }
    var key = await deriveKey(password, salt, kdf);
    var gz = await aesDecrypt(key, enc); // wrong password throws here

    var db = JSON.parse(decoder.decode(await gunzip(gz)));
    return { salt: salt, kdf: kdf, version: db.version, entries: db.entries };
  }

  /**
   * Decrypt every entry's `s` field (encrypted password) into
   * { n, u, o, l, e, password }. Legacy entries whose secret is
   * "username\0password" are migrated: login is extracted from the secret.
   */
  async function decryptEntries(entries, password, salt, params) {
    var key = await deriveKey(password, salt, params);
    var out = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var secret = await decryptWithKey(key, e.s);
      var sep = secret.indexOf('\u0000');
      var login = e.l || '';
      var pass;
      if (sep !== -1) {
        login = secret.slice(0, sep);
        pass = secret.slice(sep + 1);
      } else {
        pass = secret;
      }
      out.push({
        n: e.n,
        u: e.u,
        o: e.o,
        l: login,
        e: e.e || '',
        password: pass,
      });
    }
    return out;
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
    randomBytes: randomBytes,
    toBase64url: toBase64url,
    fromBase64url: fromBase64url,
    deriveKey: deriveKey,
    encryptSecret: encryptSecret,
    decryptSecret: decryptSecret,
    encryptWithKey: encryptWithKey,
    decryptWithKey: decryptWithKey,
    encryptDatabase: encryptDatabase,
    decryptDatabase: decryptDatabase,
    decryptEntries: decryptEntries,
  };

  global.CryptoCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
