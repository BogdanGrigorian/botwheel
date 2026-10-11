package com.botwheel;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Telegram bot (long polling) that hosts the Botwheel Vault Mini App.
 *
 * The bot does NO client-side encryption/decryption: it only stores the vault
 * transport string per user and hands it back over chat when the user taps
 * "Refresh database" (or sends /refresh). The user then opens the Mini App
 * (menu button / inline button) to unlock it with their password. The stored
 * blob may additionally be wrapped with server-side *at-rest* encryption
 * ({@link AtRestCrypto}); that layer is transparent to the client.
 */
public final class BotwheelBot {

    private static final int MAX_MESSAGE_LENGTH = 4096;

    private final BotConfig config;
    private final TelegramApi api;
    private final VaultStore store;
    private final String seedBlob; // may be null

    private BotwheelBot(BotConfig config, TelegramApi api, VaultStore store, String seedBlob) {
        this.config = config;
        this.api = api;
        this.store = store;
        this.seedBlob = seedBlob;
    }

    public static void main(String[] args) throws Exception {
        BotConfig config = BotConfig.load();
        TelegramApi api = new TelegramApi(config.botToken);

        Map<String, Object> me = api.getMe();
        String username = Json.str(Json.obj(me.get("result")).get("username"));
        System.out.println("Authorized as @" + username);

        String seedBlob = loadSeed(config.seedFile);
        if (seedBlob != null) {
            System.out.println("Seed vault loaded (" + seedBlob.length() + " chars) from " + config.seedFile);
        }

        AtRestCrypto atRest = AtRestCrypto.resolve(config.dbKey, config.dbKeyFile, System.out);

        try (VaultStore store = new VaultStore(config.dbPath, atRest)) {
            System.out.println("Vault database: " + config.dbPath);
            new BotwheelBot(config, api, store, seedBlob).run();
        }
    }

    private static String loadSeed(String seedFile) {
        if (seedFile == null) {
            return null;
        }
        try {
            Path p = Paths.get(seedFile);
            if (!Files.isRegularFile(p)) {
                System.out.println("No seed file at " + p.toAbsolutePath()
                        + " — bot starts with empty vaults.");
                return null;
            }
            String s = Files.readString(p, StandardCharsets.UTF_8).trim();
            return s.isEmpty() ? null : s;
        } catch (Exception e) {
            System.err.println("Could not read seed file " + seedFile + ": " + e.getMessage());
            return null;
        }
    }

    public void run() throws Exception {
        // Host the Mini App via the private-chat menu button.
        api.setChatMenuButtonWebApp("Open Vault", config.miniAppUrl);
        System.out.println("Mini App URL : " + config.miniAppUrl);
        System.out.println("Long polling started — Ctrl+C to stop.");

        long offset = 0;
        while (true) {
            List<Object> updates;
            try {
                updates = api.getUpdates(offset, 50);
            } catch (Exception e) {
                System.err.println("getUpdates failed: " + e.getMessage() + " — retrying in 3s");
                Thread.sleep(3000);
                continue;
            }
            for (Object u : updates) {
                Map<String, Object> update = Json.obj(u);
                offset = Json.num(update.get("update_id")) + 1;
                try {
                    handle(update);
                } catch (Exception e) {
                    System.err.println("Error handling update " + offset + ": " + e.getMessage());
                }
            }
        }
    }

    private void handle(Map<String, Object> update) throws Exception {
        Object cbq = update.get("callback_query");
        if (cbq != null) {
            handleCallback(Json.obj(cbq));
            return;
        }
        Object msg = update.get("message");
        if (msg != null) {
            handleMessage(Json.obj(msg));
        }
    }

    private void handleCallback(Map<String, Object> cbq) throws Exception {
        String data = Json.str(cbq.get("data"));
        String callbackId = Json.str(cbq.get("id"));
        long userId = Json.num(Json.obj(cbq.get("from")).get("id"));
        Object msg = cbq.get("message");
        long chatId = msg != null ? chatIdOf(Json.obj(msg)) : userId;

        if (!isAllowed(userId)) {
            api.answerCallbackQuery(callbackId, "403 Forbidden");
            return;
        }

        if ("refresh".equals(data)) {
            api.answerCallbackQuery(callbackId, "Sending your vault…");
            sendVault(userId, chatId);
        } else {
            api.answerCallbackQuery(callbackId, "Unknown action");
        }
    }

    private void handleMessage(Map<String, Object> message) throws Exception {
        long userId = Json.num(Json.obj(message.get("from")).get("id"));
        long chatId = chatIdOf(message);

        if (!isAllowed(userId)) {
            api.sendMessage(chatId, "403 Forbidden", null);
            return;
        }

        String text = Json.str(message.get("text"));
        if (text == null) {
            return; // non-text message — upload path is out of scope for now
        }
        text = text.trim();

        if (text.startsWith("/start") || text.startsWith("/help")) {
            welcome(userId, chatId);
        } else if (text.startsWith("/refresh")) {
            sendVault(userId, chatId);
        }
        // Any other message is ignored: the Mini App -> bot upload is not wired up yet.
    }

    private void welcome(long userId, long chatId) throws Exception {
        maybeSeed(userId);
        refreshMenuButton(userId, chatId);
        String text = "\uD83D\uDD10 Botwheel Vault\n\n"
                + "This bot stores your encrypted vault and hands it back to you over chat. "
                + "Tap \u201CRefresh database\u201D to receive your vault, then open the Mini App to unlock it.";
        api.sendMessage(chatId, text, mainKeyboard(userId));
    }

    private Map<String, Object> mainKeyboard(long userId) {
        Map<String, Object> refreshBtn = new LinkedHashMap<>();
        refreshBtn.put("text", "Refresh database");
        refreshBtn.put("callback_data", "refresh");

        Map<String, Object> webApp = new LinkedHashMap<>();
        webApp.put("url", miniAppUrl(userId));
        Map<String, Object> openBtn = new LinkedHashMap<>();
        openBtn.put("text", "Open Vault");
        openBtn.put("web_app", webApp);

        Map<String, Object> markup = new LinkedHashMap<>();
        markup.put("inline_keyboard", List.of(List.of(refreshBtn), List.of(openBtn)));
        return markup;
    }

    private void sendVault(long userId, long chatId) throws Exception {
        maybeSeed(userId);
        refreshMenuButton(userId, chatId);
        VaultStore.Entry entry = store.get(userId);
        if (entry == null || entry.blob == null || entry.blob.isEmpty()) {
            api.sendMessage(chatId,
                    "No vault stored yet. Your database will appear here once the Mini App "
                            + "sends it back (the upload path is not wired up yet).",
                    null);
            return;
        }
        String blob = entry.blob;
        // Wrap the vault in a <pre> block so the user can tap it to copy.
        String text = "Your encrypted vault (v" + entry.version + "):\n\n<pre>" + blob + "</pre>";
        if (text.length() <= MAX_MESSAGE_LENGTH) {
            api.sendMessage(chatId, text, null, "HTML");
        } else {
            api.sendMessage(chatId,
                    "Your vault is too large for a single message — sending it as a file.", null);
            api.sendDocument(chatId, "vault-v" + entry.version + ".txt", blob);
        }
    }

    private void maybeSeed(long userId) {
        if (seedBlob != null) {
            store.seedIfAbsent(userId, seedBlob);
        }
    }

    /**
     * The Mini App URL with this user's current vault revision stamped in.
     * The Mini App reads {@code v}/{@code t}/{@code c} and compares them with
     * the copy it cached in localStorage to decide whether it is up to date.
     */
    private String miniAppUrl(long userId) {
        VaultStore.Entry entry = store.get(userId);
        if (entry == null) {
            return config.miniAppUrl;
        }
        String sep = config.miniAppUrl.contains("?") ? "&" : "?";
        return config.miniAppUrl + sep
                + "v=" + entry.version
                + "&t=" + entry.updatedAtMillis
                + "&c=" + entry.checksum;
    }

    /** Keep the per-chat "Open Vault" quick-access button at the current revision. */
    private void refreshMenuButton(long userId, long chatId) {
        try {
            api.setChatMenuButtonWebApp(chatId, "Open Vault", miniAppUrl(userId));
        } catch (Exception e) {
            System.err.println("Could not update menu button for chat " + chatId + ": " + e.getMessage());
        }
    }

    private boolean isAllowed(long userId) {
        return config.allowedUserIds.isEmpty() || config.allowedUserIds.contains(userId);
    }

    private static long chatIdOf(Map<String, Object> message) {
        return Json.num(Json.obj(message.get("chat")).get("id"));
    }
}
