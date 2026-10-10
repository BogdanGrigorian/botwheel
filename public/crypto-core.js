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
 *   Vault (transport):       "VLT1:<base64url(salt || iv || ct || tag)>.<8-hex-checksum>"
 */

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Constants
  // -------------------------------------------------------------------------

  var DEFAULT_ITERATIONS = 600000; // PBKDF2-SHA256 rounds (OWASP recommendation)
  var SALT_BYTES = 16;             // PBKDF2 salt
  var IV_BYTES = 12;               // AES-GCM nonce (96-bit)

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

  /** Derive a 256-bit AES-GCM CryptoKey from a password + salt. */
  async function deriveKey(password, salt, iterations) {
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
   * Pipeline: JSON -> gzip -> AES-256-GCM -> base64url -> "VLT1:<body>.<checksum>".
   * opts: { salt?: Uint8Array, iterations?: number }
   */
  async function encryptDatabase(entries, password, opts) {
    opts = opts || {};
    var rounds = opts.iterations || DEFAULT_ITERATIONS;
    var salt = opts.salt || randomBytes(SALT_BYTES);
    var key = await deriveKey(password, salt, rounds);

    var json = encoder.encode(JSON.stringify({ version: 3, entries: entries }));
    var gz = await gzip(json);
    var enc = await aesEncrypt(key, gz);

    var body = toBase64url(concatBytes(salt, enc));
    var checksum = (await sha256Hex(body)).slice(0, 8);

    return 'VLT1:' + body + '.' + checksum;
  }

  /**
   * Decrypt a transport string back into { salt, version, entries }.
   * Throws on wrong password (GCM auth failure) or damaged copy (checksum).
   */
  async function decryptDatabase(str, password, iterations) {
    if (typeof str !== 'string' || str.slice(0, 5) !== 'VLT1:') {
      throw new Error('decryptDatabase: bad vault format');
    }
    var payload = str.slice(5);
    var dot = payload.lastIndexOf('.');
    var body = payload.slice(0, dot);
    var checksum = payload.slice(dot + 1);

    var expected = (await sha256Hex(body)).slice(0, 8);
    if (checksum !== expected) {
      throw new Error('decryptDatabase: checksum mismatch (damaged copy?)');
    }

    var raw = fromBase64url(body);
    var salt = raw.subarray(0, SALT_BYTES);
    var enc = raw.subarray(SALT_BYTES);
    var key = await deriveKey(password, salt, iterations);
    var gz = await aesDecrypt(key, enc); // wrong password throws here

    var db = JSON.parse(decoder.decode(await gunzip(gz)));
    return { salt: salt, version: db.version, entries: db.entries };
  }

  /**
   * Decrypt every entry's `s` field (encrypted password) into
   * { n, u, o, l, e, password }. Legacy entries whose secret is
   * "username\0password" are migrated: login is extracted from the secret.
   */
  async function decryptEntries(entries, password, salt, iterations) {
    var key = await deriveKey(password, salt, iterations);
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
