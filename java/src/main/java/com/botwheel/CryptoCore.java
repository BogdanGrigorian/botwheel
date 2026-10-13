package com.botwheel;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * CryptoCore — Java port of crypto-core.js.
 *
 * Produces the exact same output formats as the browser version, so a vault
 * generated here can be opened by the Mini App and vice versa:
 *
 *   Record (one row):    "r1.<base64url(iv || ct || tag)>"
 *                        plaintext = canonical JSON {n,u,o,l,e,p}
 *   Vault header:        base64url( kdfHeader(13) || salt(16) )   (the "key spec")
 *   Vault (container):   "VLT3:<base64url(header || gzip(recordsJson))>.<8-hex>"
 *                        recordsJson = [{"i":"<recordId>","d":"r1.…"}, …]
 *   Update payload:      "VUP1:<headerB64>\nadd:<id>:<r1.…>\ndel:<id>\nnote: …"
 *
 * The database is a set of independently encrypted records; the container is
 * the header plus those opaque records (no whole-vault encryption), so the
 * server can assemble it from its rows without ever seeing the password.
 *
 * The 13-byte KDF header (little-endian) self-describes the key derivation:
 *   id(1) || p1(4) || p2(4) || p3(4)
 *   argon2id: p1 = memory KiB, p2 = iterations, p3 = parallelism
 *   pbkdf2  : p1 = iterations
 *
 * Argon2id comes from Bouncy Castle (pure Java, test-only scope); everything
 * else uses JDK built-ins (javax.crypto, java.util.zip, java.util.Base64).
 */
public final class CryptoCore {

    public static final int DEFAULT_ITERATIONS = 600000; // PBKDF2-SHA256 rounds (legacy)
    public static final int SALT_BYTES = 16;             // PBKDF2/Argon2 salt
    public static final int IV_BYTES = 12;               // AES-GCM nonce (96-bit)

    // KDF identifiers + vault header layout.
    public static final int KDF_PBKDF2 = 1;
    public static final int KDF_ARGON2ID = 2;
    public static final int HEADER_BYTES = 13;           // id(1) || p1(4) || p2(4) || p3(4)
    public static final int HEADER_SALT_BYTES = HEADER_BYTES + SALT_BYTES; // 29 - the vault key spec

    // Record + container formats.
    public static final String RECORD_PREFIX = "r1.";
    public static final String VAULT_PREFIX = "VLT3:";
    public static final String OP_PREFIX = "VUP1:";
    public static final int RECORD_ID_HEX = 16;          // chars taken from the record-id hash

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoCore() {}

    // ------------------------------------------------------------------
    // Data shapes (mirror the JS record structure)
    // ------------------------------------------------------------------

    /**
     * A plaintext record (client-side shape).
     * n = title (mandatory), u = url (optional), o = notes (optional),
     * l = login (optional), e = email (optional), p = password (mandatory).
     * Every field is encrypted together inside the record's ciphertext, so the
     * server never sees any of them.
     */
    public static class Record {
        public String n;
        public String u;
        public String o;
        public String l;
        public String e;
        public String p;

        public Record() {}

        public Record(String n, String u, String o, String l, String e, String p) {
            this.n = n;
            this.u = u;
            this.o = o;
            this.l = l;
            this.e = e;
            this.p = p;
        }
    }

    /** One stored database row: its content id + opaque ciphertext. */
    public static class StoredRecord {
        public final String id;
        public final String cipher;

        public StoredRecord(String id, String cipher) {
            this.id = id;
            this.cipher = cipher;
        }
    }

    /** A parsed container (header + rows); no password needed. */
    public static class VaultStructure {
        public String headerB64;
        public String checksum;
        public List<StoredRecord> records;
    }

    /** KDF choice carried in the vault header (mirrors normalizeKdf in JS). */
    public static final class KdfParams {
        public final String id;   // "argon2id" | "pbkdf2"
        public final int memoryKiB;
        public final int iterations;
        public final int parallelism;

        private KdfParams(String id, int memoryKiB, int iterations, int parallelism) {
            this.id = id;
            this.memoryKiB = memoryKiB;
            this.iterations = iterations;
            this.parallelism = parallelism;
        }

        public static KdfParams argon2id(int memoryKiB, int iterations, int parallelism) {
            return new KdfParams("argon2id", memoryKiB, iterations, parallelism);
        }

        public static KdfParams pbkdf2(int iterations) {
            return new KdfParams("pbkdf2", 0, iterations, 0);
        }

        /** Matches DEFAULT_ARGON2 in crypto-core.js. */
        public static final KdfParams DEFAULT_ARGON2 = argon2id(65536, 3, 1);
    }

    // ------------------------------------------------------------------
    // Random + base64url + hashing
    // ------------------------------------------------------------------

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Unpadded base64url, matching JS toBase64url. */
    public static String toBase64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] fromBase64url(String str) {
        return Base64.getUrlDecoder().decode(str);
    }

    public static String sha256Hex(String str) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Key derivation + AES-GCM
    // ------------------------------------------------------------------

    /** PBKDF2-SHA256 -> 256-bit AES key (legacy). */
    public static SecretKeySpec deriveKey(String password, byte[] salt, int iterations) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /** Argon2id (Bouncy Castle) -> 256-bit AES key. UTF-8 password, like WebCrypto/hash-wasm. */
    public static SecretKeySpec deriveKeyArgon2(String password, byte[] salt, KdfParams p) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(p.iterations)
                .withMemoryAsKB(p.memoryKiB)
                .withParallelism(p.parallelism)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[32];
        gen.generateBytes(password.toCharArray(), out);
        return new SecretKeySpec(out, "AES");
    }

    /** Derive a 256-bit AES key, dispatching on the KDF id (null -> PBKDF2 legacy). */
    public static SecretKeySpec deriveKey(String password, byte[] salt, KdfParams kdf) throws Exception {
        if (kdf != null && "argon2id".equals(kdf.id)) {
            return deriveKeyArgon2(password, salt, kdf);
        }
        return deriveKey(password, salt, kdf != null ? kdf.iterations : DEFAULT_ITERATIONS);
    }

    // --- Self-describing KDF header, 13 bytes, little-endian ---

    private static void writeU32(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xff);
        b[off + 1] = (byte) ((v >>> 8) & 0xff);
        b[off + 2] = (byte) ((v >>> 16) & 0xff);
        b[off + 3] = (byte) ((v >>> 24) & 0xff);
    }

    private static int readU32(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    static byte[] encodeKdfHeader(KdfParams p) {
        byte[] b = new byte[HEADER_BYTES];
        if ("argon2id".equals(p.id)) {
            b[0] = (byte) KDF_ARGON2ID;
            writeU32(b, 1, p.memoryKiB);
            writeU32(b, 5, p.iterations);
            writeU32(b, 9, p.parallelism);
        } else {
            b[0] = (byte) KDF_PBKDF2;
            writeU32(b, 1, p.iterations);
        }
        return b;
    }

    static KdfParams decodeKdfHeader(byte[] b) {
        int id = b[0] & 0xff;
        if (id == KDF_ARGON2ID) {
            return KdfParams.argon2id(readU32(b, 1), readU32(b, 5), readU32(b, 9));
        }
        if (id == KDF_PBKDF2) {
            return KdfParams.pbkdf2(readU32(b, 1));
        }
        throw new IllegalArgumentException("decodeKdfHeader: unknown KDF id " + id);
    }

    /** AES-256-GCM encrypt. Returns iv || ciphertext || tag. */
    public static byte[] aesEncrypt(SecretKeySpec key, byte[] plaintext) throws Exception {
        byte[] iv = randomBytes(IV_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext); // ciphertext || 16-byte tag
        return concat(iv, ct);
    }

    /** AES-256-GCM decrypt. `blob` is iv || ciphertext || tag. */
    public static byte[] aesDecrypt(SecretKeySpec key, byte[] blob) throws Exception {
        byte[] iv = Arrays.copyOfRange(blob, 0, IV_BYTES);
        byte[] ct = Arrays.copyOfRange(blob, IV_BYTES, blob.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }

    // ------------------------------------------------------------------
    // gzip (standard RFC 1952 — interoperable with CompressionStream)
    // ------------------------------------------------------------------

    public static byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(data);
        }
        return bos.toByteArray();
    }

    public static byte[] gunzip(byte[] data) throws IOException {
        try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(data));
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = gz.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    // ------------------------------------------------------------------
    // Records (one independently encrypted database row)
    // ------------------------------------------------------------------

    /** Canonical JSON of a record - fixed key order, no stray whitespace. */
    public static String canonicalRecord(Record r) {
        return canonicalRecord(r.n, r.u, r.o, r.l, r.e, r.p);
    }

    public static String canonicalRecord(String n, String u, String o, String l, String e, String p) {
        return "{\"n\":" + jsonString(n)
                + ",\"u\":" + jsonString(u)
                + ",\"o\":" + jsonString(o)
                + ",\"l\":" + jsonString(l)
                + ",\"e\":" + jsonString(e)
                + ",\"p\":" + jsonString(p) + "}";
    }

    /** Content hash of a record: the row key it is stored under. */
    public static String recordId(String canonicalJson) throws Exception {
        return sha256Hex(canonicalJson).substring(0, RECORD_ID_HEX);
    }

    /** Encrypt one record with the vault key -> "r1.<base64url(iv||ct||tag)>". */
    public static String encryptRecord(SecretKeySpec key, String canonicalJson) throws Exception {
        byte[] enc = aesEncrypt(key, canonicalJson.getBytes(StandardCharsets.UTF_8));
        return RECORD_PREFIX + toBase64url(enc);
    }

    /** Reverse of encryptRecord -> a plaintext Record. */
    public static Record decryptRecord(SecretKeySpec key, String cipher) throws Exception {
        if (cipher == null || !cipher.startsWith(RECORD_PREFIX)) {
            throw new IllegalArgumentException("decryptRecord: bad record format");
        }
        byte[] enc = fromBase64url(cipher.substring(RECORD_PREFIX.length()));
        return parseRecord(new String(aesDecrypt(key, enc), StandardCharsets.UTF_8));
    }

    /** Parse a canonical record JSON back into a Record. */
    public static Record parseRecord(String json) {
        Object root = new JsonParser(json).parse();
        if (!(root instanceof Map)) {
            throw new IllegalArgumentException("record JSON must be an object");
        }
        Map<?, ?> m = (Map<?, ?>) root;
        Record r = new Record();
        r.n = asString(m.get("n"));
        r.u = asString(m.get("u"));
        r.o = asString(m.get("o"));
        r.l = asString(m.get("l"));
        r.e = asString(m.get("e"));
        r.p = asString(m.get("p"));
        return r;
    }

    private static String asString(Object o) {
        return o == null ? "" : (String) o;
    }

    // ------------------------------------------------------------------
    // Vault header (KDF params + salt) shared by every record
    // ------------------------------------------------------------------

    /** base64url(kdfHeader(13) || salt(16)). */
    public static String encodeVaultHeader(KdfParams kdf, byte[] salt) {
        return toBase64url(concat(encodeKdfHeader(kdf), salt));
    }

    public static KdfParams headerKdf(String headerB64) {
        return decodeKdfHeader(Arrays.copyOfRange(fromBase64url(headerB64), 0, HEADER_BYTES));
    }

    public static byte[] headerSalt(String headerB64) {
        byte[] raw = fromBase64url(headerB64);
        if (raw.length != HEADER_SALT_BYTES) {
            throw new IllegalArgumentException("vault header: expected " + HEADER_SALT_BYTES
                    + " bytes, got " + raw.length);
        }
        return Arrays.copyOfRange(raw, HEADER_BYTES, HEADER_SALT_BYTES);
    }

    /** A fresh vault header (Argon2id defaults + a new salt). */
    public static String newVaultHeader() {
        return encodeVaultHeader(KdfParams.DEFAULT_ARGON2, randomBytes(SALT_BYTES));
    }

    // ------------------------------------------------------------------
    // The container (VLT3): header + gzip(records) + a content revision
    // ------------------------------------------------------------------

    /** Content revision of a record set -> the container suffix / the "?c=" stamp. */
    public static String revisionOf(List<StoredRecord> records) throws Exception {
        List<StoredRecord> sorted = new ArrayList<>(records);
        sorted.sort((a, b) -> a.id.compareTo(b.id));
        StringBuilder sb = new StringBuilder();
        for (StoredRecord r : sorted) {
            sb.append(r.id).append(':').append(r.cipher).append('\n');
        }
        return sha256Hex(sb.toString()).substring(0, 8);
    }

    private static String recordsJson(List<StoredRecord> records) {
        List<StoredRecord> sorted = new ArrayList<>(records);
        sorted.sort((a, b) -> a.id.compareTo(b.id));
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < sorted.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"i\":").append(jsonString(sorted.get(i).id))
              .append(",\"d\":").append(jsonString(sorted.get(i).cipher)).append('}');
        }
        return sb.append(']').toString();
    }

    /** Assemble "VLT3:<base64url(header || gzip(records))>.<8hex>". */
    public static String buildVault(String headerB64, List<StoredRecord> records) throws Exception {
        byte[] gz = gzip(recordsJson(records).getBytes(StandardCharsets.UTF_8));
        String body = toBase64url(concat(fromBase64url(headerB64), gz));
        return VAULT_PREFIX + body + "." + revisionOf(records);
    }

    /**
     * Pull the container ("VLT3:…") out of a possibly larger text - the user may
     * copy the whole file content - and drop any trailing text. "" when absent.
     */
    public static String extractTransport(String str) {
        if (str == null) {
            return "";
        }
        String s = str.trim();
        int at = s.indexOf(VAULT_PREFIX);
        if (at < 0) {
            return "";
        }
        s = s.substring(at);
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) {
                s = s.substring(0, i);
                break;
            }
        }
        return s;
    }

    /** Split a container into its header + opaque rows. No password needed. */
    public static VaultStructure parseVaultStructure(String str) throws Exception {
        String payload = extractTransport(str);
        if (payload.isEmpty()) {
            throw new IllegalArgumentException(
                    "parseVaultStructure: not a vault string (expected \"VLT3:...\")");
        }
        String body = payload.substring(VAULT_PREFIX.length());
        int dot = body.lastIndexOf('.');
        if (dot < 0) {
            throw new IllegalArgumentException("parseVaultStructure: missing checksum");
        }
        String checksum = body.substring(dot + 1);
        byte[] raw = fromBase64url(body.substring(0, dot));
        if (raw.length < HEADER_SALT_BYTES) {
            throw new IllegalArgumentException("parseVaultStructure: truncated container");
        }
        byte[] gz = Arrays.copyOfRange(raw, HEADER_SALT_BYTES, raw.length);
        Object root = new JsonParser(new String(gunzip(gz), StandardCharsets.UTF_8)).parse();
        List<StoredRecord> records = new ArrayList<>();
        for (Object o : (List<?>) root) {
            Map<?, ?> m = (Map<?, ?>) o;
            records.add(new StoredRecord((String) m.get("i"), (String) m.get("d")));
        }
        VaultStructure out = new VaultStructure();
        out.headerB64 = toBase64url(Arrays.copyOfRange(raw, 0, HEADER_SALT_BYTES));
        out.checksum = checksum;
        out.records = records;
        return out;
    }

    /** Decrypt every row of a container -> plaintext records (same order). */
    public static List<Record> openRecords(VaultStructure vault, String password) throws Exception {
        SecretKeySpec key = deriveKey(password, headerSalt(vault.headerB64), headerKdf(vault.headerB64));
        List<Record> out = new ArrayList<>();
        for (StoredRecord r : vault.records) {
            out.add(decryptRecord(key, r.cipher));
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Minimal JSON (only the schema we produce/consume)
    // ------------------------------------------------------------------

    /** JSON-escape a string (public so callers can reuse it). */
    public static String jsonString(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) {
            len += a.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, off, a.length);
            off += a.length;
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Tiny JSON parser (objects, arrays, strings, numbers, booleans, null)
    // ------------------------------------------------------------------

    private static final class JsonParser {
        private final String s;
        private int i;

        JsonParser(String s) {
            this.s = s;
        }

        Object parse() {
            Object v = value();
            skipWs();
            return v;
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        private Object value() {
            skipWs();
            char c = s.charAt(i);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            if (c == 't') {
                expect("true");
                return Boolean.TRUE;
            }
            if (c == 'f') {
                expect("false");
                return Boolean.FALSE;
            }
            if (c == 'n') {
                expect("null");
                return null;
            }
            return number();
        }

        private void expect(String word) {
            if (!s.startsWith(word, i)) {
                throw new IllegalArgumentException("Expected " + word + " at " + i);
            }
            i += word.length();
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            expectChar('{');
            skipWs();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                skipWs();
                String key = string();
                skipWs();
                expectChar(':');
                m.put(key, value());
                skipWs();
                char c = next();
                if (c == '}') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("Expected ',' or '}' at " + (i - 1));
                }
            }
            return m;
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            expectChar('[');
            skipWs();
            if (peek() == ']') {
                i++;
                return l;
            }
            while (true) {
                l.add(value());
                skipWs();
                char c = next();
                if (c == ']') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("Expected ',' or ']' at " + (i - 1));
                }
            }
            return l;
        }

        private String string() {
            expectChar('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char e = next();
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            int cp = Integer.parseInt(s.substring(i, i + 4), 16);
                            sb.append((char) cp);
                            i += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("Bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Double number() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            return Double.parseDouble(s.substring(start, i));
        }

        private char peek() {
            skipWs();
            return s.charAt(i);
        }

        private char next() {
            return s.charAt(i++);
        }

        private void expectChar(char c) {
            char got = next();
            if (got != c) {
                throw new IllegalArgumentException("Expected '" + c + "' got '" + got + "' at " + (i - 1));
            }
        }
    }
}
