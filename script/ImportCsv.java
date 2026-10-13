/*
 * ImportCsv - turn an Excel-exported credentials CSV into a ready-to-use vault
 * container (VLT3) for the Botwheel Mini App / bot database. Normally launched by
 * import-csv.cmd, but it can also be run by hand:
 *
 *     javac -encoding UTF-8 -cp java\target\classes -d %TEMP%\import-csv-classes ImportCsv.java
 *     java -cp "java\target\classes;bcprov-jdk18on-1.78.1.jar;%TEMP%\import-csv-classes" ^
 *          ImportCsv creds.csv vault.txt --passphrase passphrase.key
 *
 * TWO CSV LAYOUTS (comma separated, Excel quoting, first row = header, skipped):
 *
 *   1) legacy (default)
 *        Description 1 | Description 2 | Username | Password | Email | Note
 *        n = title    <- Description 2                                 (mandatory)
 *        u = url      <- Description 1, but when Description 1 is not a URL and
 *                        Description 2 contains one, that URL is used instead
 *        l = login    <- Username                              (stored plaintext)
 *        e = email    <- Email                                 (stored plaintext)
 *        o = notes    <- Note
 *        s = password <- Password                              (encrypted below)
 *
 *   2) browser export - pass --browser-vault
 *        name | url | username | password | note
 *        n = title    <- name                                          (mandatory)
 *        u = url      <- url (or a URL found in name when url is empty)
 *        l / e        <- username: it goes to the e-mail field when it looks
 *                        like an address, to the login field otherwise
 *        o = notes    <- note
 *        s = password <- password                              (encrypted below)
 *
 * The layout comes from --browser-vault. Without the flag it is guessed from
 * the header: "name,url,username,password,note" picks the browser layout,
 * anything else the legacy one - so a forgotten flag cannot silently push a
 * note into the e-mail field.
 *
 * VALIDITY: n and s are mandatory in the vault schema, so a row is used only
 * when the title and the password are both non-empty. Invalid rows are NOT
 * imported - they are written unchanged (original columns, original content, no
 * extra "reason" column) to "<input>-invalid.csv"; the reason breakdown goes to
 * the console.
 *
 * ENCRYPTION (mirrors the Mini App, so the result opens there with the same
 * passphrase):
 *     each record -> "r1.<base64url(iv || ct || tag)>"        with the vault key
 *                    plaintext = canonical JSON {n,u,o,l,e,p}
 *     container   -> header + gzip([{"i":id,"d":cipher},...])
 *                 -> "VLT3:<base64url(header||gzip(records))>.<8-hex-revision>"
 * The key is derived from the passphrase file (raw text, default
 * passphrase.key) with Argon2id 64 MiB / 3 iterations / 1 lane and a 16-byte
 * salt, all described by the container's 29-byte header (KDF params + salt).
 * Appending reuses the existing container's header, so records already in it
 * keep decrypting with the very same key.
 *
 * The container is exactly what the bot sends back as a .txt file, so the bot
 * can ingest it (split it into rows, no crypto needed) or the Mini App can open
 * it. No at-rest (SRV1.) wrapper is added here - VaultStore does that.
 *
 * Exit codes: 0 ok, 2 usage/input problem, 3 encryption or file problem.
 */

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import com.botwheel.CryptoCore;

public final class ImportCsv {

    /* -------------------------------------------------------- csv layouts -- */
    private static final int LAYOUT_LEGACY = 0;   // Description 1, Description 2, Username, Password, Email, Note
    private static final int LAYOUT_BROWSER = 1;  // name, url, username, password, note

    private static final int EXPECTED_COLUMNS_LEGACY = 6;
    private static final int C_DESCR1 = 0;
    private static final int C_DESCR2 = 1;
    private static final int C_USERNAME = 2;
    private static final int C_PASSWORD = 3;
    private static final int C_EMAIL = 4;
    private static final int C_NOTE = 5;

    private static final int EXPECTED_COLUMNS_BROWSER = 5;
    private static final int B_NAME = 0;
    private static final int B_URL = 1;
    private static final int B_USERNAME = 2;
    private static final int B_PASSWORD = 3;
    private static final int B_NOTE = 4;

    /* Header of a browser export (Edge/Chrome/Firefox), lower case. */
    private static final List<String> BROWSER_HEADER =
            List.of("name", "url", "username", "password", "note");

    private static final Charset CP1252 = Charset.forName("windows-1252");

    private static final String DEFAULT_PASSPHRASE_FILE = "passphrase.key";
    private static final String DEFAULT_VAULT_FILE = "vault.txt";

    public static void main(String[] args) {
        Path csv = null;
        Path vaultOut = null;
        Path passFile = null;
        String saltValue = null;
        Integer layoutArg = null;
        boolean freshRequested = false;
        boolean dedupe = false;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--help".equalsIgnoreCase(arg) || "-h".equalsIgnoreCase(arg)) {
                usage(System.out);
                return;
            }
            if ("--browser-vault".equalsIgnoreCase(arg) || "-b".equalsIgnoreCase(arg)) {
                layoutArg = LAYOUT_BROWSER;
            } else if ("--legacy".equalsIgnoreCase(arg)) {
                layoutArg = LAYOUT_LEGACY;
            } else if ("--fresh".equalsIgnoreCase(arg) || "--new".equalsIgnoreCase(arg)) {
                freshRequested = true;
            } else if ("--dedupe".equalsIgnoreCase(arg)) {
                dedupe = true;
            } else if ("--passphrase".equalsIgnoreCase(arg) || "-p".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    fail("--passphrase needs a file path", 2);
                }
                passFile = Paths.get(args[++i]);
            } else if ("--salt".equalsIgnoreCase(arg)) {
                if (i + 1 >= args.length) {
                    fail("--salt needs a base64url value", 2);
                }
                saltValue = args[++i].trim();
            } else if (arg.startsWith("-") && arg.length() > 1) {
                fail("unexpected argument: " + arg, 2);
            } else if (csv == null) {
                csv = Paths.get(arg);
            } else if (vaultOut == null) {
                vaultOut = Paths.get(arg);
            } else {
                fail("unexpected argument: " + arg, 2);
            }
        }

        if (csv == null) {
            usage(System.err);
            System.exit(2);
            return;
        }

        csv = csv.toAbsolutePath().normalize();
        vaultOut = (vaultOut == null ? Paths.get(DEFAULT_VAULT_FILE) : vaultOut)
                .toAbsolutePath().normalize();
        passFile = (passFile == null ? Paths.get(DEFAULT_PASSPHRASE_FILE) : passFile)
                .toAbsolutePath().normalize();

        if (!Files.isRegularFile(csv)) {
            fail("CSV file not found: " + csv, 2);
        }
        if (!Files.isRegularFile(passFile)) {
            fail("passphrase file not found: " + passFile
                    + System.lineSeparator()
                    + "       Put the vault passphrase into it (one line, raw text) and retry.", 2);
        }

        String passphrase;
        try {
            passphrase = readPassphrase(passFile);
        } catch (IOException e) {
            fail("cannot read " + passFile + ": " + e.getMessage(), 2);
            return;
        }
        if (passphrase.isEmpty()) {
            fail("the passphrase file is empty: " + passFile, 2);
        }

        byte[] requestedSalt = null;
        if (saltValue != null && !saltValue.isEmpty()) {
            try {
                requestedSalt = CryptoCore.fromBase64url(saltValue);
            } catch (RuntimeException e) {
                fail("--salt is not valid base64url: " + saltValue, 2);
                return;
            }
            if (requestedSalt.length != CryptoCore.SALT_BYTES) {
                fail("--salt must decode to " + CryptoCore.SALT_BYTES + " bytes (got "
                        + requestedSalt.length + ")", 2);
            }
        }

        System.out.println("CSV        : " + csv);
        System.out.println("Passphrase : " + passFile + "   (read, never printed)");
        System.out.println("Vault out  : " + vaultOut);

        /* An existing vault is never replaced behind your back: it is opened with
         * the passphrase, its records are kept and the CSV rows are appended to
         * them. Its header (KDF + salt) is reused, so every record already in it
         * keeps decrypting with the very same key. */
        List<CryptoCore.StoredRecord> stored = new ArrayList<>();
        List<Pending> pending = new ArrayList<>();
        Set<String> known = new HashSet<>();      // identity (title+login+e-mail), for --dedupe
        Set<String> knownIds = new HashSet<>();   // content ids already in the vault
        int existingCount = 0;
        boolean replacing = false;
        boolean existingOutput = Files.isRegularFile(vaultOut);
        String headerB64 = null;

        if (!freshRequested && existingOutput) {
            String existing;
            try {
                existing = new String(Files.readAllBytes(vaultOut), StandardCharsets.UTF_8).trim();
            } catch (IOException e) {
                fail("cannot read the existing " + vaultOut + ": " + e.getMessage(), 3);
                return;
            }
            if (!existing.isEmpty()) {
                CryptoCore.VaultStructure opened;
                List<CryptoCore.Record> openedRecords;
                try {
                    opened = CryptoCore.parseVaultStructure(existing);
                    openedRecords = CryptoCore.openRecords(opened, passphrase);
                } catch (Exception e) {
                    fail("cannot open the existing vault " + vaultOut + ": " + e.getMessage()
                            + System.lineSeparator()
                            + "       Same passphrase as the one that built it? Use --fresh to"
                            + " start over from the CSV alone.", 3);
                    return;
                }
                headerB64 = opened.headerB64;
                existingCount = opened.records.size();
                replacing = true;
                if (requestedSalt != null
                        && !CryptoCore.toBase64url(requestedSalt)
                                .equals(CryptoCore.toBase64url(CryptoCore.headerSalt(headerB64)))) {
                    fail("--salt does not match the salt of the existing vault"
                            + System.lineSeparator()
                            + "       Appending keeps the existing key - drop --salt, or use --fresh.", 2);
                }
                for (CryptoCore.Record record : openedRecords) {
                    known.add(identity(record.n, record.l, record.e));
                }
                for (CryptoCore.StoredRecord record : opened.records) {
                    knownIds.add(record.id);
                }
                stored.addAll(opened.records);
                System.out.println("Existing   : " + existingCount + " records opened from "
                        + vaultOut + " - appending to them");
            }
        }
        if (headerB64 == null) {
            headerB64 = requestedSalt != null
                    ? CryptoCore.encodeVaultHeader(CryptoCore.KdfParams.DEFAULT_ARGON2, requestedSalt)
                    : CryptoCore.newVaultHeader();
        }

        List<Row> rows;
        try {
            rows = readCsv(csv);
        } catch (IOException e) {
            fail("cannot read " + csv + ": " + e.getMessage(), 2);
            return;
        }

        if (rows.size() < 2) {
            System.out.println("Nothing to do - the file has no data rows below the header.");
            System.exit(0);
            return;
        }

        Row header = rows.get(0);
        List<Row> data = rows.subList(1, rows.size());

        int detected = detectLayout(header);
        int layout = layoutArg == null ? detected : layoutArg;
        boolean browserLayout = layout == LAYOUT_BROWSER;
        System.out.println("Layout     : " + (browserLayout ? "browser export" : "legacy")
                + (layoutArg != null ? "   (from the passed option)"
                        : detected == LAYOUT_BROWSER ? "   (from the header)"
                                : "   (default; header is not a browser export)"));

        List<Row> invalid = new ArrayList<>();
        Map<String, Integer> reasons = new LinkedHashMap<>();
        int blank = 0;
        int added = 0;
        int duplicates = 0;
        int urlFromTitle = 0;
        int usernameEmails = 0;

        for (Row row : data) {
            if (row.isBlank()) {
                blank++;
                continue;
            }
            String problem = browserLayout ? validateBrowser(row) : validateLegacy(row);
            if (problem != null) {
                invalid.add(row);
                reasons.merge(problem, 1, Integer::sum);
                continue;
            }
            Mapped mapped = browserLayout ? mapBrowser(row) : mapLegacy(row);
            CryptoCore.Record record = mapped.record;
            String json = CryptoCore.canonicalRecord(record);
            String id;
            try {
                id = CryptoCore.recordId(json);
            } catch (Exception e) {
                invalid.add(row);
                reasons.merge("record id failed: " + e.getMessage(), 1, Integer::sum);
                continue;
            }
            // A record whose content is already present hashes to the same id, so
            // re-importing the same CSV never duplicates anything.
            if (knownIds.contains(id)) {
                duplicates++;
                continue;
            }
            if (dedupe && !known.add(identity(record.n, record.l, record.e))) {
                duplicates++;
                continue;
            }
            knownIds.add(id);
            pending.add(new Pending(id, json));
            added++;
            if (mapped.urlFromTitle) {
                urlFromTitle++;
            }
            if (mapped.usernameIsEmail) {
                usernameEmails++;
            }
        }

        Path invalidFile = null;
        if (!invalid.isEmpty()) {
            invalidFile = writeInvalid(csv, invalid, header);
        }

        if (added == 0) {
            System.out.println();
            System.out.println("No new records to add - nothing was encrypted or written.");
            if (existingCount > 0) {
                System.out.println("(" + existingCount + " records stay untouched in " + vaultOut + ".)");
            }
            report(data.size(), added, blank, urlFromTitle, usernameEmails,
                    browserLayout, duplicates, existingCount, invalid, invalidFile, reasons);
            System.exit(0);
            return;
        }

        String container;
        try {
            if (!pending.isEmpty()) {
                SecretKeySpec key = CryptoCore.deriveKey(passphrase,
                        CryptoCore.headerSalt(headerB64), CryptoCore.headerKdf(headerB64));
                for (Pending p : pending) {
                    stored.add(new CryptoCore.StoredRecord(
                            p.id, CryptoCore.encryptRecord(key, p.json)));
                }
            }
            container = buildVault(headerB64, stored, passphrase);
        } catch (Exception e) {
            fail("encryption failed: " + e.getMessage(), 3);
            return;
        }

        Path backup = null;
        try {
            Path parent = vaultOut.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            if (existingOutput) {
                // --fresh overwrites without reading the old file first, so the
                // backup has to happen here, not only in the append path.
                backup = vaultOut.resolveSibling(vaultOut.getFileName() + ".bak");
                Files.copy(vaultOut, backup, StandardCopyOption.REPLACE_EXISTING);
            }
            Files.write(vaultOut, container.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            fail("cannot write " + vaultOut + ": " + e.getMessage(), 3);
            return;
        }

        System.out.println();
        report(data.size(), added, blank, urlFromTitle, usernameEmails,
                browserLayout, duplicates, existingCount, invalid, invalidFile, reasons);
        System.out.println();
        System.out.println("KDF        : " + kdfLabel(CryptoCore.headerKdf(headerB64)));
        System.out.println("Header     : " + headerB64
                + (replacing ? "   (kept from the existing vault)" : "   (pass --salt to reuse the salt)"));
        System.out.println("Container  : " + container.length() + " chars, revision " + revisionOf(container));
        System.out.println("Round-trip : OK - all " + stored.size()
                + " records decrypted back with the passphrase");
        if (backup != null) {
            System.out.println("Backup     : " + backup + "   (the vault as it was before)");
        }
        System.out.println("Wrote      : " + vaultOut);
        System.out.println();
        System.out.println("Next: the bot ingests this file on the first /start (telegram.seed.file),");
        System.out.println("or paste its content into the Mini App. This tool adds no at-rest wrapper.");
        System.exit(0);
    }

    /* ---------------------------------------------------------- encryption -- */

    /** One new record waiting to be sealed (id + its canonical JSON). */
    private static final class Pending {
        final String id;
        final String json;

        Pending(String id, String json) {
            this.id = id;
            this.json = json;
        }
    }

    private static String buildVault(String headerB64, List<CryptoCore.StoredRecord> stored,
                                     String passphrase) throws Exception {
        String container = CryptoCore.buildVault(headerB64, stored);
        verify(container, passphrase, stored);
        return container;
    }

    /* Decrypt what we just built and compare the ids with the source, so a silent
     * encryption mistake can never reach the database. */
    private static void verify(String container, String passphrase,
                               List<CryptoCore.StoredRecord> expected) throws Exception {
        CryptoCore.VaultStructure structure = CryptoCore.parseVaultStructure(container);
        if (structure.records.size() != expected.size()) {
            throw new IllegalStateException("container reopened with " + structure.records.size()
                    + " records instead of " + expected.size());
        }
        Set<String> want = new HashSet<>();
        for (CryptoCore.StoredRecord record : expected) {
            want.add(record.id);
        }
        Set<String> got = new HashSet<>();
        for (CryptoCore.Record record : CryptoCore.openRecords(structure, passphrase)) {
            got.add(CryptoCore.recordId(CryptoCore.canonicalRecord(record)));
        }
        if (!want.equals(got)) {
            throw new IllegalStateException("records did not decrypt back with the passphrase");
        }
    }

    private static String kdfLabel(CryptoCore.KdfParams kdf) {
        if ("pbkdf2".equals(kdf.id)) {
            return "pbkdf2 (iterations " + kdf.iterations + ")";
        }
        return kdf.id + " (memory " + kdf.memoryKiB + " KiB, iterations "
                + kdf.iterations + ", parallelism " + kdf.parallelism + ")";
    }

    /* Identity used by --dedupe: same title, login and e-mail = same record. */
    private static String identity(String n, String l, String e) {
        return (n + "\u0000" + l + "\u0000" + e).toLowerCase(Locale.ROOT);
    }

    /** The 8-hex revision suffix of a container. */
    private static String revisionOf(String container) {
        int dot = container.lastIndexOf('.');
        return dot < 0 ? "" : container.substring(dot + 1);
    }

    /* Raw passphrase text: UTF-8 (or CP1252), BOM stripped, trailing line
     * endings removed. Inner spaces are kept as typed. */
    private static String readPassphrase(Path file) throws IOException {
        String text = decode(Files.readAllBytes(file));
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        int end = text.length();
        while (end > 0 && (text.charAt(end - 1) == '\n' || text.charAt(end - 1) == '\r')) {
            end--;
        }
        return text.substring(0, end);
    }

    /* ------------------------------------------------------------- output -- */

    private static Path writeInvalid(Path csv, List<Row> invalid, Row header) {
        Path invalidFile = sibling(csv, "-invalid.csv");
        StringBuilder out = new StringBuilder("\uFEFF"); // BOM so Excel opens UTF-8
        out.append(withNewline(header.raw));
        for (Row r : invalid) {
            out.append(withNewline(r.raw));
        }
        try {
            Files.write(invalidFile, out.toString().getBytes(StandardCharsets.UTF_8));
            return invalidFile;
        } catch (IOException e) {
            System.err.println("WARNING: could not write " + invalidFile + ": " + e.getMessage());
            return null;
        }
    }

    private static void report(int dataRows, int records, int blank, int urlFromTitle,
                               int usernameEmails, boolean browserLayout, int duplicates,
                               int kept, List<Row> invalid, Path invalidFile,
                               Map<String, Integer> reasons) {
        System.out.println("Data rows : " + dataRows + (blank > 0 ? " (" + blank + " blank skipped)" : ""));
        System.out.println("Records   : " + records + " new"
                + (kept > 0 ? " (+ " + kept + " kept from the existing vault)" : ""));
        if (duplicates > 0) {
            System.out.println("Duplicate : " + duplicates + " skipped (--dedupe)");
        }
        if (urlFromTitle > 0) {
            System.out.println("URL taken from " + (browserLayout ? "name" : "Description 2")
                    + ": " + urlFromTitle);
        }
        if (usernameEmails > 0) {
            System.out.println("Usernames stored as e-mail: " + usernameEmails);
        }
        System.out.println("Invalid   : " + invalid.size()
                + (invalidFile != null ? "  ->  " + invalidFile : ""));
        for (Map.Entry<String, Integer> e : reasons.entrySet()) {
            System.out.println("              " + e.getValue() + " x " + e.getKey());
        }
    }

    /* -------------------------------------------------------- csv layouts -- */

    /* The Edge/Chrome/Firefox export header, so a forgotten --browser-vault
     * cannot silently map the note column onto the e-mail field. Anything else
     * keeps the legacy behaviour. */
    private static int detectLayout(Row header) {
        if (header.fields.size() != BROWSER_HEADER.size()) {
            return LAYOUT_LEGACY;
        }
        for (int i = 0; i < BROWSER_HEADER.size(); i++) {
            if (!header.fields.get(i).trim().equalsIgnoreCase(BROWSER_HEADER.get(i))) {
                return LAYOUT_LEGACY;
            }
        }
        return LAYOUT_BROWSER;
    }

    /* ------------------------------------------------------------ checking -- */

    private static String validateLegacy(Row row) {
        if (row.fields.size() > EXPECTED_COLUMNS_LEGACY) {
            return "more than " + EXPECTED_COLUMNS_LEGACY + " columns";
        }
        if (value(row, C_DESCR2).isEmpty()) {
            return "missing Description 2 (title)";
        }
        if (value(row, C_PASSWORD).isEmpty()) {
            return "missing Password";
        }
        return null;
    }

    private static String validateBrowser(Row row) {
        if (row.fields.size() > EXPECTED_COLUMNS_BROWSER) {
            return "more than " + EXPECTED_COLUMNS_BROWSER + " columns";
        }
        if (value(row, B_NAME).isEmpty()) {
            return "missing name (title)";
        }
        if (value(row, B_PASSWORD).isEmpty()) {
            return "missing password";
        }
        return null;
    }

    /* ------------------------------------------------------------- mapping -- */

    /* One CSV row mapped onto a vault record, plus what the mapping decided. */
    private static final class Mapped {
        final CryptoCore.Record record;
        final boolean urlFromTitle;
        final boolean usernameIsEmail;

        Mapped(CryptoCore.Record record, boolean urlFromTitle, boolean usernameIsEmail) {
            this.record = record;
            this.urlFromTitle = urlFromTitle;
            this.usernameIsEmail = usernameIsEmail;
        }
    }

    private static Mapped mapLegacy(Row row) {
        String d1 = value(row, C_DESCR1);
        String d2 = value(row, C_DESCR2);
        String link = d1;
        boolean fromTitle = false;
        if (!looksLikeUrl(d1)) {
            String inTitle = urlInText(d2);
            if (!inTitle.isEmpty()) {
                link = inTitle;
                fromTitle = true;
            }
        }
        CryptoCore.Record record = new CryptoCore.Record(d2, link, value(row, C_NOTE),
                value(row, C_USERNAME), value(row, C_EMAIL), value(row, C_PASSWORD));
        return new Mapped(record, fromTitle, false);
    }

    /* Browser export: the single "username" column has to serve both the login
     * and the e-mail field, so it is sorted by shape. */
    private static Mapped mapBrowser(Row row) {
        String name = value(row, B_NAME);
        String link = value(row, B_URL);
        boolean fromTitle = false;
        if (link.isEmpty()) {
            String inTitle = urlInText(name);
            if (!inTitle.isEmpty()) {
                link = inTitle;
                fromTitle = true;
            }
        }
        String user = value(row, B_USERNAME);
        boolean isEmail = looksLikeEmail(user);
        CryptoCore.Record record = new CryptoCore.Record(name, link, value(row, B_NOTE),
                isEmail ? "" : user, isEmail ? user : "", value(row, B_PASSWORD));
        return new Mapped(record, fromTitle, isEmail);
    }

    /* A username is treated as an address only when it really looks like one:
     * no spaces, exactly one @, and a domain with a dot and text around it.
     * Anything else ("admin", "Pinwheels_", "5f9b34fb", "Bogdan") is a login. */
    private static boolean looksLikeEmail(String s) {
        if (s.isEmpty() || s.indexOf(' ') >= 0) {
            return false;
        }
        int at = s.indexOf('@');
        if (at <= 0 || at != s.lastIndexOf('@')) {
            return false;
        }
        String domain = s.substring(at + 1);
        int dot = domain.indexOf('.');
        return dot > 0 && dot < domain.length() - 1;
    }

    private static String value(Row row, int index) {
        return index < row.fields.size() ? row.fields.get(index).trim() : "";
    }

    /* --------------------------------------------------------------- urls -- */

    /* A whole field counts as a link when it is a URL, a www.-host or a bare
     * domain; anywhere inside a longer text only a scheme/www. token counts, so
     * ordinary sentences do not turn into links. */
    private static String urlInText(String text) {
        if (text == null) {
            return "";
        }
        String trimmed = trimEdgePunctuation(text.trim());
        if (looksLikeUrl(trimmed)) {
            return trimmed;
        }
        for (String token : text.split("\\s+")) {
            String candidate = trimEdgePunctuation(token);
            if (hasSchemeOrHost(candidate)) {
                return candidate;
            }
        }
        return "";
    }

    private static boolean looksLikeUrl(String s) {
        return hasSchemeOrHost(s) || isBareDomain(s);
    }

    private static boolean hasSchemeOrHost(String s) {
        if (s.isEmpty()) {
            return false;
        }
        String lower = s.toLowerCase(Locale.ROOT);
        return lower.startsWith("http://") || lower.startsWith("https://")
                || lower.startsWith("ftp://") || lower.startsWith("www.");
    }

    private static boolean isBareDomain(String s) {
        if (s.isEmpty() || s.indexOf(' ') >= 0) {
            return false;
        }
        return s.toLowerCase(Locale.ROOT)
                .matches("[a-z0-9][a-z0-9-]*(\\.[a-z0-9-]+)*\\.[a-z]{2,}(/\\S*)?");
    }

    private static String trimEdgePunctuation(String s) {
        int start = 0;
        int end = s.length();
        String edges = "()[]{}<>\",;'`";
        while (start < end && (edges.indexOf(s.charAt(start)) >= 0 || s.charAt(start) == '.')) {
            start++;
        }
        while (end > start && (edges.indexOf(s.charAt(end - 1)) >= 0 || s.charAt(end - 1) == '.')) {
            end--;
        }
        return s.substring(start, end);
    }

    /* ---------------------------------------------------------------- csv -- */

    private static List<Row> readCsv(Path file) throws IOException {
        String text = decode(Files.readAllBytes(file));
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        List<Row> rows = new ArrayList<>();
        int length = text.length();
        int i = 0;
        while (i < length) {
            int start = i;
            List<String> fields = new ArrayList<>();
            StringBuilder field = new StringBuilder();
            boolean quoted = false;
            boolean endOfRecord = false;
            while (!endOfRecord) {
                if (i >= length) {
                    fields.add(field.toString());
                    break;
                }
                char c = text.charAt(i);
                if (quoted) {
                    if (c == '"') {
                        if (i + 1 < length && text.charAt(i + 1) == '"') {
                            field.append('"');
                            i += 2;
                        } else {
                            quoted = false;
                            i++;
                        }
                    } else {
                        field.append(c);
                        i++;
                    }
                } else if (c == '"' && field.length() == 0) {
                    quoted = true;
                    i++;
                } else if (c == ',') {
                    fields.add(field.toString());
                    field.setLength(0);
                    i++;
                } else if (c == '\r') {
                    i++;
                    if (i < length && text.charAt(i) == '\n') {
                        i++;
                    }
                    fields.add(field.toString());
                    endOfRecord = true;
                } else if (c == '\n') {
                    i++;
                    fields.add(field.toString());
                    endOfRecord = true;
                } else {
                    field.append(c);
                    i++;
                }
            }
            rows.add(new Row(fields, text.substring(start, i)));
        }
        return rows;
    }

    private static String decode(byte[] bytes) {
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException notUtf8) {
            return new String(bytes, CP1252);
        }
    }

    private static Path sibling(Path csv, String suffix) {
        String name = csv.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;
        return csv.resolveSibling(base + suffix);
    }

    private static String withNewline(String raw) {
        int end = raw.length();
        while (end > 0 && (raw.charAt(end - 1) == '\n' || raw.charAt(end - 1) == '\r')) {
            end--;
        }
        return raw.substring(0, end) + System.lineSeparator();
    }

    private static final class Row {
        final List<String> fields;
        final String raw;

        Row(List<String> fields, String raw) {
            this.fields = fields;
            this.raw = raw;
        }

        boolean isBlank() {
            for (String field : fields) {
                if (!field.trim().isEmpty()) {
                    return false;
                }
            }
            return true;
        }
    }

    private static void fail(String message, int code) {
        System.err.println("ERROR: " + message);
        System.exit(code);
    }

    private static void usage(PrintStream out) {
        out.println("Usage: import-csv.cmd <csv-file> [vault-out] [--browser-vault]");
        out.println("                     [--fresh] [--dedupe] [--passphrase <file>]");
        out.println("                     [--salt <base64url>]");
        out.println();
        out.println("  <csv-file>             CSV exported from Excel / a browser password manager");
        out.println("                         (header row is skipped)");
        out.println("  [vault-out]            vault container to add the records to");
        out.println("                         (default: " + DEFAULT_VAULT_FILE + ")");
        out.println("                         when it already exists it is opened with the");
        out.println("                         passphrase and the CSV rows are APPENDED to its");
        out.println("                         records; the old file is kept as <vault>.bak");
        out.println("  [--fresh]              ignore an existing vault and start a new one");
        out.println("                         (overwrites it, still keeping <vault>.bak)");
        out.println("  [--dedupe]             skip rows whose title + login + e-mail are already");
        out.println("                         in the vault (identical records always collapse)");
        out.println("  [--browser-vault]      read a browser export instead of the legacy layout:");
        out.println("                           name,url,username,password,note");
        out.println("                         'username' lands in the e-mail field when it looks");
        out.println("                         like an address, in the login field otherwise");
        out.println("                         (also picked up automatically from that header)");
        out.println("  [--passphrase <file>]  file holding the vault passphrase as raw text");
        out.println("                         (default: " + DEFAULT_PASSPHRASE_FILE + ")");
        out.println("  [--salt <base64url>]   reuse an existing vault salt when starting fresh");
        out.println();
        out.println("Legacy layout: Description 1,Description 2,Username,Password,Email,Note");
        out.println("Each record is encrypted on its own (r1. field) and the whole vault is");
        out.println("written as a VLT3 container with a key derived from the passphrase with");
        out.println("Argon2id. The container is what the bot sends back as vault.txt.");
        out.println("Invalid rows (no title / no password) go to <csv-file>-invalid.csv.");
    }
}
