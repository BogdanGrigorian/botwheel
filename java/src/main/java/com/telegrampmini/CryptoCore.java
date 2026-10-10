package com.telegrampmini;

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

/**
 * CryptoCore — Java port of crypto-core.js.
 *
 * Produces the exact same output formats as the browser version, so a vault
 * generated here can be opened by the Mini App and vice versa:
 *
 *   Field (self-contained):  "s1.<base64url(salt || iv || ct || tag)>"
 *   Field (with key):        "s1.<base64url(iv || ct || tag)>"
 *   Vault (transport):       "VLT1:<base64url(salt || iv || ct || tag)>.<8-hex-checksum>"
 *
 * Uses only JDK built-ins (javax.crypto, java.util.zip, java.util.Base64).
 */
public final class CryptoCore {

    public static final int DEFAULT_ITERATIONS = 600000; // PBKDF2-SHA256 rounds
    public static final int SALT_BYTES = 16;             // PBKDF2 salt
    public static final int IV_BYTES = 12;               // AES-GCM nonce (96-bit)

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoCore() {}

    // ------------------------------------------------------------------
    // Data shapes (mirror the JS record structure)
    // ------------------------------------------------------------------

    /**
     * A stored record.
     * n = name/title (mandatory), u = url/domain (optional), o = notes (optional),
     * s = encrypted "username\0password" (mandatory).
     */
    public static class Entry {
        public String n;
        public String u;
        public String o;
        public String s;

        public Entry() {}

        public Entry(String n, String u, String o, String s) {
            this.n = n;
            this.u = u;
            this.o = o;
            this.s = s;
        }
    }

    /** A record after decryption. */
    public static class DecryptedEntry {
        public String n;
        public String u;
        public String o;
        public String username;
        public String password;

        public DecryptedEntry(String n, String u, String o, String username, String password) {
            this.n = n;
            this.u = u;
            this.o = o;
            this.username = username;
            this.password = password;
        }
    }

    /** Result of decryptDatabase(). */
    public static class Vault {
        public byte[] salt;
        public int version;
        public List<Entry> entries;
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

    /** PBKDF2-SHA256 -> 256-bit AES key (matches WebCrypto PBKDF2). */
    public static SecretKeySpec deriveKey(String password, byte[] salt, int iterations) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
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
        return encryptDatabase(entries, password, null, DEFAULT_ITERATIONS);
    }

    public static String encryptDatabase(List<Entry> entries, String password, byte[] salt, int iterations)
            throws Exception {
        if (salt == null) {
            salt = randomBytes(SALT_BYTES);
        }
        SecretKeySpec key = deriveKey(password, salt, iterations);
        byte[] json = toJson(entries).getBytes(StandardCharsets.UTF_8);
        byte[] gz = gzip(json);
        byte[] enc = aesEncrypt(key, gz);

        String body = toBase64url(concat(salt, enc));
        String checksum = sha256Hex(body).substring(0, 8);

        return "VLT1:" + body + "." + checksum;
    }

    public static Vault decryptDatabase(String str, String password) throws Exception {
        return decryptDatabase(str, password, DEFAULT_ITERATIONS);
    }

    public static Vault decryptDatabase(String str, String password, int iterations) throws Exception {
        if (str == null || !str.startsWith("VLT1:")) {
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
        byte[] salt = Arrays.copyOfRange(raw, 0, SALT_BYTES);
        byte[] enc = Arrays.copyOfRange(raw, SALT_BYTES, raw.length);
        SecretKeySpec key = deriveKey(password, salt, iterations);
        byte[] gz = aesDecrypt(key, enc); // wrong password => AEADBadTagException

        Vault vault = parseJson(new String(gunzip(gz), StandardCharsets.UTF_8));
        vault.salt = salt;
        return vault;
    }

    /** Unwrap every record's `s` field into { n, u, o, username, password }. */
    public static List<DecryptedEntry> decryptEntries(List<Entry> entries, String password, byte[] salt)
            throws Exception {
        return decryptEntries(entries, password, salt, DEFAULT_ITERATIONS);
    }

    public static List<DecryptedEntry> decryptEntries(List<Entry> entries, String password, byte[] salt, int iterations)
            throws Exception {
        SecretKeySpec key = deriveKey(password, salt, iterations);
        List<DecryptedEntry> out = new ArrayList<>();
        for (Entry e : entries) {
            String secret = decryptWithKey(key, e.s);
            int sep = secret.indexOf('\u0000');
            out.add(new DecryptedEntry(e.n, e.u, e.o, secret.substring(0, sep), secret.substring(sep + 1)));
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Minimal JSON (only the schema we produce/consume)
    // ------------------------------------------------------------------

    /** Serialize entries to {"version":2,"entries":[{n,u,o,s},...]}. */
    public static String toJson(List<Entry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"version\":2,\"entries\":[");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            Entry e = entries.get(i);
            sb.append("{\"n\":").append(jsonString(e.n))
              .append(",\"u\":").append(jsonString(e.u))
              .append(",\"o\":").append(jsonString(e.o))
              .append(",\"s\":").append(jsonString(e.s))
              .append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    /** JSON-escape a string (public so callers can reuse it). */
    public static String jsonString(String s) {
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
            entries.add(new Entry((String) em.get("n"), (String) em.get("u"), (String) em.get("o"), (String) em.get("s")));
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
