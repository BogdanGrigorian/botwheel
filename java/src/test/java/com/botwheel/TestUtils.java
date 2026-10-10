package com.botwheel;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * TestUtils — test-data generator for CryptoCore (no JUnit tests here).
 *
 * Produces demo vault blobs for manual testing and seeds the bot's demo vault.
 *
 * Run (from java/):
 *   .\mvnw -q test-compile exec:java "-Dexec.mainClass=com.botwheel.TestUtils"
 *   .\mvnw -q test-compile exec:java "-Dexec.mainClass=com.botwheel.TestUtils" "-Dexec.args=200"
 */
public final class TestUtils {

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

    /** Curated demo records: { title, url, notes, login, email, password }. */
    private static final String[][] DEMO_RECORDS = {
            { "GitHub", "https://github.com", "work code hosting", "octocat", "octocat@github.com", "Gh_p@ss!2024" },
            { "Google", "https://google.com", "personal mail", "jane.doe", "jane.doe@gmail.com", "Goog1e!Pass" },
            { "Netflix", "https://netflix.com", "streaming", "jane", "jane@example.com", "Str3am!ng" },
            { "Amazon", "https://amazon.com", "shopping", "jane.doe", "", "Sh0p!Pass" },
            { "Bank - Savings", "", "savings account", "janedoe", "", "B@nk#Sav1ngs" },
            { "Wi-Fi Router", "https://192.168.1.1", "home router admin", "admin", "", "R0uter!Pass" },
            { "1Password", "https://1password.com", "", "jane@example.com", "jane@example.com", "M@ster!Key" },
            { "Airbnb", "https://airbnb.com", "travel", "", "jane@example.com", "Tr@vel!2024" },
            { "Dropbox", "https://dropbox.com", "backups", "jane.doe", "jane.doe@dropbox.com", "Dr0p!B0x" },
            { "Spotify", "https://spotify.com", "music", "jane.doe", "jane.doe@spotify.com", "Mus1c!Pass" },
            { "Twitter", "https://twitter.com", "social", "janedoe", "", "Tw1tt3r!" },
            { "Steam", "https://steamcommunity.com", "gaming", "janedoe", "jane.doe@steam.com", "G@m3r!Pass" },
            { "Work VPN", "", "corporate vpn", "jdoe", "jdoe@company.com", "VPn#W0rk" },
            { "Zoo membership", "https://zoo.example.com", "", "", "", "Z00!Pass" },
    };

    private TestUtils() {}

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
     * Create n records: random login, email and password; password encrypted,
     * title/url/notes/login/email in plaintext. Returns { salt, entries }.
     */
    public static Created createRecords(int n, String password) throws Exception {
        byte[] salt = CryptoCore.randomBytes(CryptoCore.SALT_BYTES);
        SecretKeySpec key = CryptoCore.deriveKey(password, salt, CryptoCore.DEFAULT_ITERATIONS);

        List<CryptoCore.Entry> entries = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String login = "user" + randomString(6, LOGIN_ALPHABET);
            String email = login + "@" + NAMES[i % NAMES.length];
            String pass = randomString(12, PASSWORD_ALPHABET);
            String name = NAMES[i % NAMES.length] + "-" + (i + 1);
            String url = "https://" + NAMES[i % NAMES.length];
            String notes = NOTES[i % NOTES.length];
            String s = CryptoCore.encryptWithKey(key, pass);
            entries.add(new CryptoCore.Entry(name, url, notes, login, email, s));
        }

        Created c = new Created();
        c.salt = salt;
        c.entries = entries;
        return c;
    }

    /**
     * Create the curated demo vault (varied records exercising optional fields).
     */
    public static Created createDemoRecords(String password) throws Exception {
        byte[] salt = CryptoCore.randomBytes(CryptoCore.SALT_BYTES);
        SecretKeySpec key = CryptoCore.deriveKey(password, salt, CryptoCore.DEFAULT_ITERATIONS);

        List<CryptoCore.Entry> entries = new ArrayList<>();
        for (String[] row : DEMO_RECORDS) {
            String s = CryptoCore.encryptWithKey(key, row[5]);
            entries.add(new CryptoCore.Entry(row[0], row[1], row[2], row[3], row[4], s));
        }

        Created c = new Created();
        c.salt = salt;
        c.entries = entries;
        return c;
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 0;

        System.out.println("USER_PASSWORD  : \"" + USER_PASSWORD + "\"");
        System.out.println("PBKDF2 iters   : " + CryptoCore.DEFAULT_ITERATIONS);
        System.out.println(n > 0
                ? "Records        : " + n
                : "Records        : " + DEMO_RECORDS.length + " (demo set)");
        System.out.println();

        // 1) Single-field demo
        String field = CryptoCore.encryptSecret("s3cret_P@ssword!", USER_PASSWORD);
        System.out.println("Field encrypt  : " + field);
        System.out.println("Field decrypt  : " + CryptoCore.decryptSecret(field, USER_PASSWORD));
        System.out.println();

        // 2) Build a vault of records
        Created created = n > 0 ? createRecords(n, USER_PASSWORD) : createDemoRecords(USER_PASSWORD);
        CryptoCore.Entry e0 = created.entries.get(0);
        System.out.println("Salt (b64url)  : " + CryptoCore.toBase64url(created.salt));
        System.out.println("Sample entry   : {\"n\":" + CryptoCore.jsonString(e0.n)
                + ",\"u\":" + CryptoCore.jsonString(e0.u)
                + ",\"o\":" + CryptoCore.jsonString(e0.o)
                + ",\"l\":" + CryptoCore.jsonString(e0.l)
                + ",\"e\":" + CryptoCore.jsonString(e0.e)
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
                    + ",\"l\":" + CryptoCore.jsonString(e.l)
                    + ",\"e\":" + CryptoCore.jsonString(e.e)
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
                .append(",\"l\":").append(CryptoCore.jsonString(e.l))
                .append(",\"e\":").append(CryptoCore.jsonString(e.e))
                .append(",\"password\":").append(CryptoCore.jsonString(e.password))
                .append('}');
        }
        json.append("]}");
        Files.write(outJson, json.toString().getBytes(StandardCharsets.UTF_8));

        System.out.println("Wrote          : " + outTxt.toAbsolutePath());
        System.out.println("Wrote          : " + outJson.toAbsolutePath());
    }
}
