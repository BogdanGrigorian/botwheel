package com.botwheel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Bot configuration, resolved in this order:
 *   system property -> environment variable -> bot.properties -> default.
 *
 *   telegram.bot.token   / TELEGRAM_BOT_TOKEN   (required)
 *   telegram.miniapp.url / MINIAPP_URL          (GitHub Pages URL of the Mini App)
 *   telegram.seed.file   / TELEGRAM_SEED_FILE   (optional VLT3 container; split into rows on a user's first /start)
 *   telegram.allowed.user.ids / TELEGRAM_ALLOWED_USER_IDS (optional allowlist)
 *   telegram.db.path     / TELEGRAM_DB_PATH      (embedded H2 database location)
 *   telegram.db.key      / TELEGRAM_DB_KEY       (optional base64 32-byte server key)
 *   telegram.db.key.file / TELEGRAM_DB_KEY_FILE  (optional key file; created if missing)
 */
public final class BotConfig {

    public final String botToken;
    public final String miniAppUrl;
    public final String seedFile; // may be null
    public final String dbPath; // H2 database path or jdbc:h2: URL
    public final String dbKey; // base64 server-side at-rest key, or ""
    public final String dbKeyFile; // key file path, or "off" to disable
    public final Set<Long> allowedUserIds; // empty = allow everyone

    private BotConfig(String botToken, String miniAppUrl, String seedFile, String dbPath,
            String dbKey, String dbKeyFile, Set<Long> allowedUserIds) {
        this.botToken = botToken;
        this.miniAppUrl = miniAppUrl;
        this.seedFile = seedFile;
        this.dbPath = dbPath;
        this.dbKey = dbKey;
        this.dbKeyFile = dbKeyFile;
        this.allowedUserIds = allowedUserIds;
    }

    public static BotConfig load() throws IOException {
        Properties props = new Properties();
        Path propsFile = Paths.get("bot.properties");
        if (Files.isRegularFile(propsFile)) {
            try (InputStream in = Files.newInputStream(propsFile)) {
                props.load(in);
            }
        }

        String token = resolve("telegram.bot.token", "TELEGRAM_BOT_TOKEN", props, null);
        if (token == null || token.isBlank()) {
            throw new IllegalStateException(
                    "Bot token missing. Set TELEGRAM_BOT_TOKEN (or -Dtelegram.bot.token=...), "
                            + "or add telegram.bot.token=... to java/bot.properties");
        }
        token = token.trim();

        String url = resolve("telegram.miniapp.url", "MINIAPP_URL", props,
                "https://bogdangrigorian.github.io/botwheel/");

        String seed = resolve("telegram.seed.file", "TELEGRAM_SEED_FILE", props, "test-vault.txt");
        if (seed != null) {
            seed = seed.trim();
        }

        String allowedRaw = resolve("telegram.allowed.user.ids", "TELEGRAM_ALLOWED_USER_IDS", props, "");
        Set<Long> allowedUserIds = parseAllowedUsers(allowedRaw);

        String dbPath = resolve("telegram.db.path", "TELEGRAM_DB_PATH", props, "botwheel-db");
        dbPath = dbPath.trim();

        // At-rest key material: either an explicit base64 key, or a key file.
        // Default is a sibling "<db>.key" so Docker's single ./data mount stays
        // consistent; set telegram.db.key.file=off to disable, or point it at a
        // path on a separate volume for real key/DB separation.
        String dbKey = resolve("telegram.db.key", "TELEGRAM_DB_KEY", props, "").trim();
        String defaultKeyFile = dbPath.startsWith("jdbc:h2:") ? AtRestCrypto.DISABLED : dbPath + ".key";
        String dbKeyFile = resolve("telegram.db.key.file", "TELEGRAM_DB_KEY_FILE", props, defaultKeyFile).trim();

        return new BotConfig(token, url,
                (seed == null || seed.isEmpty()) ? null : seed, dbPath, dbKey, dbKeyFile, allowedUserIds);
    }

    private static Set<Long> parseAllowedUsers(String raw) {
        Set<Long> ids = new LinkedHashSet<>();
        if (raw == null || raw.isBlank()) {
            return ids;
        }
        for (String part : raw.split("[,;\\s]+")) {
            if (part.isEmpty()) {
                continue;
            }
            try {
                ids.add(Long.parseLong(part.trim()));
            } catch (NumberFormatException ignored) {
                // skip malformed entries
            }
        }
        return ids;
    }

    private static String resolve(String propKey, String envKey, Properties props, String def) {
        String v = System.getProperty(propKey);
        if (v == null || v.isBlank()) {
            v = System.getenv(envKey);
        }
        if (v == null || v.isBlank()) {
            v = props.getProperty(propKey);
        }
        if (v == null || v.isBlank()) {
            v = def;
        }
        return v;
    }
}
