package com.botwheel;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * TestUtils — test-data generator for CryptoCore (no JUnit tests here).
 *
 * Produces a demo vault container (VLT3) for manual testing and for the bot's
 * seed file.
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

    /** Result of the record builders: the vault header + the plaintext records. */
    public static class Created {
        public String headerB64;
        public List<CryptoCore.Record> records;
    }

    public static String randomString(int length, String alphabet) {
        byte[] buf = CryptoCore.randomBytes(length);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt((buf[i] & 0xff) % alphabet.length()));
        }
        return sb.toString();
    }

    /** Create n records with random login, e-mail and password. */
    public static Created createRecords(int n) {
        Created c = new Created();
        c.headerB64 = CryptoCore.newVaultHeader();
        c.records = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String login = "user" + randomString(6, LOGIN_ALPHABET);
            String email = login + "@" + NAMES[i % NAMES.length];
            String pass = randomString(12, PASSWORD_ALPHABET);
            String name = NAMES[i % NAMES.length] + "-" + (i + 1);
            String url = "https://" + NAMES[i % NAMES.length];
            String notes = NOTES[i % NOTES.length];
            c.records.add(new CryptoCore.Record(name, url, notes, login, email, pass));
        }
        return c;
    }

    /** Create the curated demo vault (varied records exercising optional fields). */
    public static Created createDemoRecords() {
        Created c = new Created();
        c.headerB64 = CryptoCore.newVaultHeader();
        c.records = new ArrayList<>();
        for (String[] row : DEMO_RECORDS) {
            c.records.add(new CryptoCore.Record(row[0], row[1], row[2], row[3], row[4], row[5]));
        }
        return c;
    }

    /** Seal the plaintext records into the VLT3 container string. */
    public static String buildContainer(Created created, String password) throws Exception {
        SecretKeySpec key = CryptoCore.deriveKey(password,
                CryptoCore.headerSalt(created.headerB64), CryptoCore.headerKdf(created.headerB64));
        List<CryptoCore.StoredRecord> stored = new ArrayList<>();
        for (CryptoCore.Record r : created.records) {
            String json = CryptoCore.canonicalRecord(r);
            stored.add(new CryptoCore.StoredRecord(
                    CryptoCore.recordId(json), CryptoCore.encryptRecord(key, json)));
        }
        return CryptoCore.buildVault(created.headerB64, stored);
    }

    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 0;

        System.out.println("USER_PASSWORD  : \"" + USER_PASSWORD + "\"");
        System.out.println("KDF            : Argon2id "
                + "(memory=" + CryptoCore.KdfParams.DEFAULT_ARGON2.memoryKiB + " KiB, "
                + "iterations=" + CryptoCore.KdfParams.DEFAULT_ARGON2.iterations + ", "
                + "parallelism=" + CryptoCore.KdfParams.DEFAULT_ARGON2.parallelism + ")");
        System.out.println(n > 0
                ? "Records        : " + n
                : "Records        : " + DEMO_RECORDS.length + " (demo set)");
        System.out.println();

        // 1) Build the plaintext records
        Created created = n > 0 ? createRecords(n) : createDemoRecords();
        CryptoCore.Record r0 = created.records.get(0);
        System.out.println("Header (b64url): " + created.headerB64);
        System.out.println("Sample record  : " + CryptoCore.canonicalRecord(r0));
        System.out.println();

        // 2) Seal them into the container the bot sends and the Mini App pastes
        String container = buildContainer(created, USER_PASSWORD);
        System.out.println("VAULT CONTAINER (" + container.length() + " chars):");
        System.out.println(container);
        System.out.println();

        // 3) Round-trip verification
        CryptoCore.VaultStructure structure = CryptoCore.parseVaultStructure(container);
        List<CryptoCore.Record> back = CryptoCore.openRecords(structure, USER_PASSWORD);
        if (back.size() != created.records.size()) {
            throw new IllegalStateException("record count changed through the round trip");
        }
        // The container stores records sorted by content id, so compare as sets.
        List<String> want = new ArrayList<>();
        for (CryptoCore.Record r : created.records) {
            want.add(CryptoCore.canonicalRecord(r));
        }
        List<String> got = new ArrayList<>();
        for (CryptoCore.Record r : back) {
            got.add(CryptoCore.canonicalRecord(r));
        }
        Collections.sort(want);
        Collections.sort(got);
        if (!want.equals(got)) {
            throw new IllegalStateException("records changed through the round trip");
        }
        System.out.println("Round-trip OK  : " + back.size() + " records decrypted");
        System.out.println("First 3 decoded:");
        for (int i = 0; i < Math.min(3, back.size()); i++) {
            System.out.println("   " + CryptoCore.canonicalRecord(back.get(i)));
        }
        System.out.println();

        // 4) Wrong password must fail
        try {
            CryptoCore.openRecords(structure, "wrong-password");
            System.out.println("Wrong password : FAILED TO DETECT (bug!)");
        } catch (Exception ex) {
            System.out.println("Wrong password : correctly rejected ("
                    + ex.getClass().getSimpleName()
                    + (ex.getMessage() != null ? ": " + ex.getMessage() : "") + ")");
        }
        System.out.println();

        // 5) Write outputs for inspection
        Path outTxt = Paths.get("test-vault.txt");
        Path outJson = Paths.get("test-vault.decrypted.json");
        Files.write(outTxt, container.getBytes(StandardCharsets.UTF_8));

        StringBuilder json = new StringBuilder();
        json.append("{\"header\":\"").append(created.headerB64).append("\",\"records\":[");
        for (int i = 0; i < back.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            CryptoCore.Record r = back.get(i);
            json.append("{\"n\":").append(CryptoCore.jsonString(r.n))
                .append(",\"u\":").append(CryptoCore.jsonString(r.u))
                .append(",\"o\":").append(CryptoCore.jsonString(r.o))
                .append(",\"l\":").append(CryptoCore.jsonString(r.l))
                .append(",\"e\":").append(CryptoCore.jsonString(r.e))
                .append(",\"p\":").append(CryptoCore.jsonString(r.p))
                .append('}');
        }
        json.append("]}");
        Files.write(outJson, json.toString().getBytes(StandardCharsets.UTF_8));

        System.out.println("Wrote          : " + outTxt.toAbsolutePath());
        System.out.println("Wrote          : " + outJson.toAbsolutePath());
    }
}
