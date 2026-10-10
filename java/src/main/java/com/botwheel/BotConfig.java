package com.botwheel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Bot configuration, resolved in this order:
 *   system property -> environment variable -> bot.properties -> default.
 *
 *   telegram.bot.token   / TELEGRAM_BOT_TOKEN   (required)
 *   telegram.miniapp.url / MINIAPP_URL          (GitHub Pages URL of the Mini App)
 *   telegram.seed.file   / TELEGRAM_SEED_FILE   (optional demo vault blob)
 */
public final class BotConfig {

    public final String botToken;
    public final String miniAppUrl;
    public final String seedFile; // may be null

    private BotConfig(String botToken, String miniAppUrl, String seedFile) {
        this.botToken = botToken;
        this.miniAppUrl = miniAppUrl;
        this.seedFile = seedFile;
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

        return new BotConfig(token, url, (seed == null || seed.isEmpty()) ? null : seed);
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
