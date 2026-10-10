package com.telegrampmini;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * CryptoTest — debug/test tool for CryptoCore.
 *
 * Run:
 *   javac CryptoCore.java CryptoTest.java
 *   java CryptoTest            # 5 demo records
 *   java CryptoTest 200        # 200 records
 */
public final class CryptoTest {

    private static final String USER_PASSWORD = "ChangeMe_TestPass123!";

    private static final String[] NAMES = {
            "steam", "github.com", "google.com", "amazon.com", "netflix.com",
            "paypal.com", "spotify.com", "discord.com", "reddit.com", "dropbox.com",
    };

    private static final String[] NOTES = {
            "main steam account", "work account", "personal", "shopping",
            "streaming", "finance", "music", "chat", "news", "backups",
    };

    private static final String PASSWORD_ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*";
    private static final String LOGIN_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";

    private CryptoTest() {}

    /** Result of createRecords(). */
    public static class Created {
        public byte[] salt;
        public List<CryptoCore.Entry> entries;
    }

    public static String randomString(int length, String alphabet) {
        byte[] buf = CryptoCore.randomBytes(length);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt((buf[i] & 0xff) % alphabet.length()));
        }
        return sb.toString();
    }

    /**
     * Create n records: random login + password, password encrypted,
     * resource and tags in plaintext. Returns { salt, entries }.
     */
    public static Created createRecords(int n, String password) throws Exception {
        byte[] salt = CryptoCore.randomBytes(CryptoCore.SALT_BYTES);
        SecretKeySpec key = CryptoCore.deriveKey(password, salt, CryptoCore.DEFAULT_ITERATIONS);

        List<CryptoCore.Entry> entries = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String username = "user" + randomString(6, LOGIN_ALPHABET);
            String pass = randomString(12, PASSWORD_ALPHABET);
            String name = NAMES[i % NAMES.length] + "-" + (i + 1);
            String url = "https://" + NAMES[i % NAMES.length];
            String notes = NOTES[i % NOTES.length];
            String s = CryptoCore.encryptWithKey(key, username + '\u0000' + pass);
            entries.add(new CryptoCore.Entry(name, url, notes, s));
        }

        Created c = new Created();
        c.salt = salt;
        c.entries = entries;
        return c;
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 5;

        System.out.println("USER_PASSWORD  : \"" + USER_PASSWORD + "\"");
        System.out.println("PBKDF2 iters   : " + CryptoCore.DEFAULT_ITERATIONS);
        System.out.println("Records        : " + n);
        System.out.println();

        // 1) Single-field demo
        String field = CryptoCore.encryptSecret("s3cret_P@ssword!", USER_PASSWORD);
        System.out.println("Field encrypt  : " + field);
        System.out.println("Field decrypt  : " + CryptoCore.decryptSecret(field, USER_PASSWORD));
        System.out.println();

        // 2) Build a vault of n records
        Created created = createRecords(n, USER_PASSWORD);
        CryptoCore.Entry e0 = created.entries.get(0);
        System.out.println("Salt (b64url)  : " + CryptoCore.toBase64url(created.salt));
        System.out.println("Sample entry   : {\"n\":" + CryptoCore.jsonString(e0.n)
                + ",\"u\":" + CryptoCore.jsonString(e0.u)
                + ",\"o\":" + CryptoCore.jsonString(e0.o)
                + ",\"s\":" + CryptoCore.jsonString(e0.s) + "}");
        System.out.println();

        // 3) The transport string
        String blob = CryptoCore.encryptDatabase(
                created.entries, USER_PASSWORD, created.salt, CryptoCore.DEFAULT_ITERATIONS);
        System.out.println("VAULT BLOB (" + blob.length() + " chars):");
        System.out.println(blob);
        System.out.println();
        System.out.println("Fits in a Telegram message (<=4096)? "
                + (blob.length() <= 4096 ? "YES" : "NO"));
        System.out.println();

        // 4) Round-trip verification
        CryptoCore.Vault vault = CryptoCore.decryptDatabase(blob, USER_PASSWORD);
        List<CryptoCore.DecryptedEntry> decrypted =
                CryptoCore.decryptEntries(vault.entries, USER_PASSWORD, vault.salt);
        System.out.println("Round-trip OK  : " + decrypted.size() + " entries decrypted");
        System.out.println("First 3 decoded:");
        for (int i = 0; i < Math.min(3, decrypted.size()); i++) {
            CryptoCore.DecryptedEntry e = decrypted.get(i);
            System.out.println("   {\"n\":" + CryptoCore.jsonString(e.n)
                    + ",\"u\":" + CryptoCore.jsonString(e.u)
                    + ",\"o\":" + CryptoCore.jsonString(e.o)
                    + ",\"username\":" + CryptoCore.jsonString(e.username)
                    + ",\"password\":" + CryptoCore.jsonString(e.password) + "}");
        }
        System.out.println();

        // 5) Wrong password must fail
        try {
            CryptoCore.decryptDatabase(blob, "wrong-password");
            System.out.println("Wrong password : FAILED TO DETECT (bug!)");
        } catch (Exception ex) {
            System.out.println("Wrong password : correctly rejected ("
                    + ex.getClass().getSimpleName()
                    + (ex.getMessage() != null ? ": " + ex.getMessage() : "") + ")");
        }
        System.out.println();

        // 6) Write outputs for inspection
        Path outTxt = Paths.get("test-vault.txt");
        Path outJson = Paths.get("test-vault.decrypted.json");
        Files.write(outTxt, blob.getBytes(StandardCharsets.UTF_8));

        StringBuilder json = new StringBuilder();
        json.append("{\"salt\":\"").append(CryptoCore.toBase64url(created.salt)).append("\",\"entries\":[");
        for (int i = 0; i < decrypted.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            CryptoCore.DecryptedEntry e = decrypted.get(i);
            json.append("{\"n\":").append(CryptoCore.jsonString(e.n))
                .append(",\"u\":").append(CryptoCore.jsonString(e.u))
                .append(",\"o\":").append(CryptoCore.jsonString(e.o))
                .append(",\"username\":").append(CryptoCore.jsonString(e.username))
                .append(",\"password\":").append(CryptoCore.jsonString(e.password))
                .append('}');
        }
        json.append("]}");
        Files.write(outJson, json.toString().getBytes(StandardCharsets.UTF_8));

        System.out.println("Wrote          : " + outTxt.toAbsolutePath());
        System.out.println("Wrote          : " + outJson.toAbsolutePath());
    }
}
