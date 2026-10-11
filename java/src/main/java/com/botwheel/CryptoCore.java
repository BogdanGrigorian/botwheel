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
 *   Field (self-contained):  "s1.<base64url(salt || iv || ct || tag)>"
 *   Field (with key):        "s1.<base64url(iv || ct || tag)>"
 *   Vault (transport):       "VLT2:<base64url(header || salt || iv || ct || tag)>.<8-hex-checksum>"
 *   Vault (legacy):          "VLT1:<base64url(salt || iv || ct || tag)>.<8-hex-checksum>"
 *
 * The VLT2 header (13 bytes, little-endian) self-describes the KDF:
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

    // KDF identifiers + VLT2 header layout.
    public static final int KDF_PBKDF2 = 1;
    public static final int KDF_ARGON2ID = 2;
    public static final int HEADER_BYTES = 13;           // id(1) || p1(4) || p2(4) || p3(4)

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoCore() {}

    // ------------------------------------------------------------------
    // Data shapes (mirror the JS record structure)
    // ------------------------------------------------------------------

    /**
     * A stored record.
     * n = name/title (mandatory), u = url/domain (optional), o = notes (optional),
     * l = login/username (optional, plaintext), e = email (optional, plaintext),
     * s = encrypted password (mandatory).
     */
    public static class Entry {
        public String n;
        public String u;
        public String o;
        public String l;
        public String e;
        public String s;

        public Entry() {}

        public Entry(String n, String u, String o, String s) {
            this(n, u, o, null, null, s);
        }

        public Entry(String n, String u, String o, String l, String e, String s) {
            this.n = n;
            this.u = u;
            this.o = o;
            this.l = l;
            this.e = e;
            this.s = s;
        }
    }

    /** A record after decryption. */
    public static class DecryptedEntry {
        public String n;
        public String u;
        public String o;
        public String l;
        public String e;
        public String password;

        public DecryptedEntry(String n, String u, String o, String l, String e, String password) {
            this.n = n;
            this.u = u;
            this.o = o;
            this.l = l;
            this.e = e;
            this.password = password;
        }
    }

    /** Result of decryptDatabase(). */
    public static class Vault {
        public byte[] salt;
        public KdfParams kdf;
        public int version;
        public List<Entry> entries;
    }

    /** KDF choice carried in the VLT2 header (mirrors normalizeKdf in JS). */
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

    /** PBKDF2-SHA256 -> 256-bit AES key (legacy VLT1 path). */
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

    // --- Self-describing KDF header (VLT2), 13 bytes, little-endian ---

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
        throw new IllegalArgumentException("decryptDatabase: unknown KDF id " + id);
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
    // Field encryption
    // ------------------------------------------------------------------

    /** Encrypt a single string with a password (self-contained salt). */
    public static String encryptSecret(String plaintext, String password) throws Exception {
        return encryptSecret(plaintext, password, DEFAULT_ITERATIONS);
    }

    public static String encryptSecret(String plaintext, String password, int iterations) throws Exception {
        byte[] salt = randomBytes(SALT_BYTES);
        SecretKeySpec key = deriveKey(password, salt, iterations);
        byte[] enc = aesEncrypt(key, plaintext.getBytes(StandardCharsets.UTF_8));
        return "s1." + toBase64url(concat(salt, enc));
    }

    public static String decryptSecret(String encoded, String password) throws Exception {
        return decryptSecret(encoded, password, DEFAULT_ITERATIONS);
    }

    public static String decryptSecret(String encoded, String password, int iterations) throws Exception {
        if (encoded == null || !encoded.startsWith("s1.")) {
            throw new IllegalArgumentException("decryptSecret: bad field format");
        }
        byte[] raw = fromBase64url(encoded.substring(3));
        byte[] salt = Arrays.copyOfRange(raw, 0, SALT_BYTES);
        byte[] enc = Arrays.copyOfRange(raw, SALT_BYTES, raw.length);
        SecretKeySpec key = deriveKey(password, salt, iterations);
        return new String(aesDecrypt(key, enc), StandardCharsets.UTF_8);
    }

    /** Bulk: encrypt with an already-derived key (no salt inside). */
    public static String encryptWithKey(SecretKeySpec key, String plaintext) throws Exception {
        byte[] enc = aesEncrypt(key, plaintext.getBytes(StandardCharsets.UTF_8));
        return "s1." + toBase64url(enc);
    }

    public static String decryptWithKey(SecretKeySpec key, String encoded) throws Exception {
        if (encoded == null || !encoded.startsWith("s1.")) {
            throw new IllegalArgumentException("decryptWithKey: bad field format");
        }
        byte[] enc = fromBase64url(encoded.substring(3));
        return new String(aesDecrypt(key, enc), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // Whole-database (vault) encryption
    // ------------------------------------------------------------------

    public static String encryptDatabase(List<Entry> entries, String password) throws Exception {
        return encryptDatabase(entries, password, null, KdfParams.DEFAULT_ARGON2);
    }

    public static String encryptDatabase(List<Entry> entries, String password, byte[] salt, KdfParams kdf)
            throws Exception {
        if (salt == null) {
            salt = randomBytes(SALT_BYTES);
        }
        if (kdf == null) {
            kdf = KdfParams.DEFAULT_ARGON2;
        }
        SecretKeySpec key = deriveKey(password, salt, kdf);
        byte[] json = toJson(entries).getBytes(StandardCharsets.UTF_8);
        byte[] gz = gzip(json);
        byte[] enc = aesEncrypt(key, gz);

        String body = toBase64url(concat(encodeKdfHeader(kdf), salt, enc));
        String checksum = sha256Hex(body).substring(0, 8);

        return "VLT2:" + body + "." + checksum;
    }

    public static Vault decryptDatabase(String str, String password) throws Exception {
        if (str == null || str.length() < 5) {
            throw new IllegalArgumentException("decryptDatabase: bad vault format");
        }
        String tag = str.substring(0, 5);
        if (!tag.equals("VLT2:") && !tag.equals("VLT1:")) {
            throw new IllegalArgumentException("decryptDatabase: bad vault format");
        }
        String payload = str.substring(5);
        int dot = payload.lastIndexOf('.');
        String body = payload.substring(0, dot);
        String checksum = payload.substring(dot + 1);

        String expected = sha256Hex(body).substring(0, 8);
        if (!checksum.equals(expected)) {
            throw new IllegalArgumentException("decryptDatabase: checksum mismatch (damaged copy?)");
        }

        byte[] raw = fromBase64url(body);
        KdfParams kdf;
        byte[] salt;
        byte[] enc;
        if (tag.equals("VLT2:")) {
            kdf = decodeKdfHeader(Arrays.copyOfRange(raw, 0, HEADER_BYTES));
            salt = Arrays.copyOfRange(raw, HEADER_BYTES, HEADER_BYTES + SALT_BYTES);
            enc = Arrays.copyOfRange(raw, HEADER_BYTES + SALT_BYTES, raw.length);
        } else {
            kdf = KdfParams.pbkdf2(DEFAULT_ITERATIONS);
            salt = Arrays.copyOfRange(raw, 0, SALT_BYTES);
            enc = Arrays.copyOfRange(raw, SALT_BYTES, raw.length);
        }
        SecretKeySpec key = deriveKey(password, salt, kdf);
        byte[] gz = aesDecrypt(key, enc); // wrong password => AEADBadTagException

        Vault vault = parseJson(new String(gunzip(gz), StandardCharsets.UTF_8));
        vault.salt = salt;
        vault.kdf = kdf;
        return vault;
    }

    /** Unwrap every record's `s` field (encrypted password) into { n, u, o, l, e, password }. */
    public static List<DecryptedEntry> decryptEntries(List<Entry> entries, String password, byte[] salt)
            throws Exception {
        return decryptEntries(entries, password, salt, KdfParams.pbkdf2(DEFAULT_ITERATIONS));
    }

    public static List<DecryptedEntry> decryptEntries(List<Entry> entries, String password, byte[] salt, int iterations)
            throws Exception {
        return decryptEntries(entries, password, salt, KdfParams.pbkdf2(iterations));
    }

    public static List<DecryptedEntry> decryptEntries(List<Entry> entries, String password, byte[] salt, KdfParams kdf)
            throws Exception {
        SecretKeySpec key = deriveKey(password, salt, kdf);
        List<DecryptedEntry> out = new ArrayList<>();
        for (Entry e : entries) {
            String secret = decryptWithKey(key, e.s);
            int sep = secret.indexOf('\u0000');
            String login = e.l != null ? e.l : "";
            String pass;
            if (sep != -1) {
                // legacy "username\0password"
                login = secret.substring(0, sep);
                pass = secret.substring(sep + 1);
            } else {
                pass = secret;
            }
            out.add(new DecryptedEntry(e.n, e.u, e.o, login, e.e != null ? e.e : "", pass));
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Minimal JSON (only the schema we produce/consume)
    // ------------------------------------------------------------------

    /** Serialize entries to {"version":3,"entries":[{n,u,o,l,e,s},...]}. */
    public static String toJson(List<Entry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"version\":3,\"entries\":[");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            Entry e = entries.get(i);
            sb.append("{\"n\":").append(jsonString(e.n))
              .append(",\"u\":").append(jsonString(e.u))
              .append(",\"o\":").append(jsonString(e.o))
              .append(",\"l\":").append(jsonString(e.l))
              .append(",\"e\":").append(jsonString(e.e))
              .append(",\"s\":").append(jsonString(e.s))
              .append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

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

    /** Parse the JSON we produce into a Vault (version + entries). */
    public static Vault parseJson(String jsonStr) {
        Object root = new JsonParser(jsonStr).parse();
        if (!(root instanceof Map)) {
            throw new IllegalArgumentException("vault JSON must be an object");
        }
        Map<?, ?> m = (Map<?, ?>) root;
        Vault v = new Vault();
        v.version = ((Number) m.get("version")).intValue();
        List<Entry> entries = new ArrayList<>();
        for (Object o : (List<?>) m.get("entries")) {
            Map<?, ?> em = (Map<?, ?>) o;
            entries.add(new Entry(
                    (String) em.get("n"),
                    (String) em.get("u"),
                    (String) em.get("o"),
                    (String) em.get("l"),
                    (String) em.get("e"),
                    (String) em.get("s")));
        }
        v.entries = entries;
        return v;
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
