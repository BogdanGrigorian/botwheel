package com.botwheel;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Telegram bot (long polling) that hosts the Botwheel Vault Mini App.
 *
 * The bot does NO client-side encryption/decryption. It stores one opaque
 * ciphertext per record plus the small vault header (KDF params + salt), and
 * reassembles them into a single container that it sends as a .txt file when
 * the user taps "Refresh database" (or sends /refresh). The Mini App applies a
 * change with a small per-record payload (VUP1:…) — always well under the
 * 4096-character message limit — which the bot applies to its rows. Everything
 * the bot stores may additionally be wrapped with server-side *at-rest*
 * encryption ({@link AtRestCrypto}); that layer is transparent to the client.
 */
public final class BotwheelBot {

    private final BotConfig config;
    private final TelegramApi api;
    private final VaultStore store;
    private final String seedContainer; // a VLT3 container string, or null
    private final Set<Long> menuResetChats = new HashSet<>();

    private BotwheelBot(BotConfig config, TelegramApi api, VaultStore store, String seedContainer) {
        this.config = config;
        this.api = api;
        this.store = store;
        this.seedContainer = seedContainer;
    }

    public static void main(String[] args) throws Exception {
        BotConfig config = BotConfig.load();
        TelegramApi api = new TelegramApi(config.botToken);

        Map<String, Object> me = api.getMe();
        String username = Json.str(Json.obj(me.get("result")).get("username"));
        System.out.println("Authorized as @" + username);

        String seedContainer = loadSeed(config.seedFile);
        if (seedContainer != null) {
            System.out.println("Seed vault loaded from " + config.seedFile);
        }

        AtRestCrypto atRest = AtRestCrypto.resolve(config.dbKey, config.dbKeyFile, System.out);

        try (VaultStore store = new VaultStore(config.dbPath, atRest)) {
            System.out.println("Vault database: " + config.dbPath);
            new BotwheelBot(config, api, store, seedContainer).run();
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
        // The Mini App is reachable ONLY through the reply-keyboard button — the
        // one launch type that lets it sendData() back to us — so point every
        // menu button at the command list instead of a Web App.
        try {
            api.setChatMenuButtonCommands(null);
        } catch (Exception e) {
            System.err.println("Could not reset the menu button: " + e.getMessage());
        }
        try {
            api.setMyCommands(commandList());
        } catch (Exception e) {
            System.err.println("Could not register commands: " + e.getMessage());
        }
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
        ensureMenuReset(chatId);

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
        ensureMenuReset(chatId);

        // A message pushed by the Mini App via Telegram.WebApp.sendData() arrives
        // as a service message: "/refresh" ("hand me the latest vault") or a
        // small per-record update (VUP1:…) to apply.
        Object webAppData = message.get("web_app_data");
        if (webAppData != null) {
            String data = Json.str(Json.obj(webAppData).get("data"));
            String trimmed = data == null ? "" : data.trim();
            if (trimmed.startsWith("/refresh") || trimmed.equals("refresh")) {
                sendVault(userId, chatId);
            } else if (trimmed.startsWith("/start") || trimmed.startsWith("/help")) {
                welcome(userId, chatId);
            } else if (trimmed.startsWith(CryptoCore.OP_PREFIX)) {
                applyUpdate(userId, chatId, trimmed);
            } else {
                api.sendMessage(chatId, "Unrecognised Mini App command.", null);
            }
            return;
        }

        String text = Json.str(message.get("text"));
        if (text == null) {
            return; // non-text message — nothing else to do
        }
        text = text.trim();

        if (text.startsWith("/start") || text.startsWith("/help")) {
            welcome(userId, chatId);
        } else if (text.startsWith("/refresh")) {
            sendVault(userId, chatId);
        } else if (text.startsWith(CryptoCore.OP_PREFIX) || text.startsWith("/update")) {
            applyUpdate(userId, chatId, text);
        }
        // Anything else is ignored.
    }

    private void welcome(long userId, long chatId) throws Exception {
        maybeSeed(userId);
        String text = "\uD83D\uDD10 Botwheel Vault\n\n"
                + "This bot stores your encrypted vault and hands it back to you on request. "
                + "Tap \u201CRefresh database\u201D to receive it as a file \u2014 open the file, copy its "
                + "whole content and paste it into the Mini App's database field to unlock it.";
        api.sendMessage(chatId, text, mainKeyboard());
        api.sendMessage(chatId,
                "Use the \u201COpen Vault\u201D keyboard button below the message field to open, "
                        + "edit and save records \u2014 each change is sent back to me automatically.",
                updateKeyboard(userId));
    }

    private Map<String, Object> mainKeyboard() {
        Map<String, Object> refreshBtn = new LinkedHashMap<>();
        refreshBtn.put("text", "Refresh database");
        refreshBtn.put("callback_data", "refresh");

        Map<String, Object> markup = new LinkedHashMap<>();
        markup.put("inline_keyboard", List.of(List.of(refreshBtn)));
        return markup;
    }

    /**
     * Reply keyboard with a {@code web_app} button. Launching the Mini App this
     * way (rather than from an inline/menu button) is what lets it call
     * {@code Telegram.WebApp.sendData()} to push the vault back to the bot.
     */
    private Map<String, Object> updateKeyboard(long userId) {
        Map<String, Object> webApp = new LinkedHashMap<>();
        webApp.put("url", miniAppUrl(userId));

        Map<String, Object> button = new LinkedHashMap<>();
        button.put("text", "Open Vault");
        button.put("web_app", webApp);

        Map<String, Object> markup = new LinkedHashMap<>();
        markup.put("keyboard", List.of(List.of(button)));
        markup.put("resize_keyboard", true);
        return markup;
    }

    private void sendVault(long userId, long chatId) throws Exception {
        maybeSeed(userId);
        VaultStore.Snapshot snap = store.snapshot(userId);
        if (snap == null || snap.header.isEmpty()) {
            api.sendMessage(chatId,
                    "No vault stored yet. Create it in the Mini App and send it back here "
                            + "(open the vault with the keyboard button below).",
                    updateKeyboard(userId));
            return;
        }
        // The container is just the header + the opaque records, so the server
        // can assemble it without ever seeing the password. It always goes out
        // as a file: the database can outgrow a 4096-char message.
        String container = CryptoCore.buildVault(snap.header, snap.records);
        String caption = "\uD83D\uDD10 Your encrypted vault (v" + snap.version + ", "
                + snap.size() + " record" + (snap.size() == 1 ? "" : "s") + ").\n"
                + "Open the file, copy its whole content and paste it into the Mini App.";
        api.sendDocument(chatId, "vault-v" + snap.version + ".txt", container, caption,
                updateKeyboard(userId));
    }

    private void maybeSeed(long userId) {
        if (seedContainer == null) {
            return;
        }
        try {
            CryptoCore.VaultStructure structure = CryptoCore.parseVaultStructure(seedContainer);
            store.seedIfAbsent(userId, structure.headerB64, structure.records);
        } catch (Exception e) {
            System.err.println("Could not seed the vault from " + config.seedFile + ": " + e.getMessage());
        }
    }

    /**
     * Apply a small per-record payload sent by the Mini App (via sendData() or
     * pasted into the chat) and bump the user's revision.
     */
    private void applyUpdate(long userId, long chatId, String raw) throws Exception {
        UpdatePayload payload = UpdatePayload.parse(raw);
        if (payload == null) {
            api.sendMessage(chatId,
                    "Could not read that update. Send the string the Mini App produced (\"VUP1:\u2026\").",
                    null);
            return;
        }
        VaultStore.Snapshot snap = store.applyOps(userId, payload.headerB64, payload.ops);
        // Re-send the keyboard so its Mini App URL carries the new revision.
        api.sendMessage(chatId,
                "Vault updated to v" + snap.version + " \u2014 " + snap.size() + " record"
                        + (snap.size() == 1 ? "" : "s")
                        + (payload.note.isEmpty() ? "" : "  \u00b7  " + payload.note),
                updateKeyboard(userId));
    }

    private static List<Map<String, Object>> commandList() {
        return List.of(
                command("start", "Show the welcome message"),
                command("refresh", "Receive your encrypted vault as a file"));
    }

    private static Map<String, Object> command(String name, String description) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("command", name);
        m.put("description", description);
        return m;
    }

    /**
     * The Mini App URL with this user's current vault revision stamped in.
     * The Mini App reads {@code v}/{@code t}/{@code c} and compares them with
     * the copy it cached in localStorage to decide whether it is up to date.
     */
    private String miniAppUrl(long userId) {
        VaultStore.Snapshot snap = store.snapshot(userId);
        if (snap == null) {
            return config.miniAppUrl;
        }
        String checksum;
        try {
            checksum = CryptoCore.revisionOf(snap.records);
        } catch (Exception e) {
            checksum = "";
        }
        String sep = config.miniAppUrl.contains("?") ? "&" : "?";
        return config.miniAppUrl + sep
                + "v=" + snap.version
                + "&t=" + snap.updatedAtMillis
                + "&c=" + checksum;
    }

    private boolean isAllowed(long userId) {
        return config.allowedUserIds.isEmpty() || config.allowedUserIds.contains(userId);
    }

    /**
     * A per-chat menu button set by an older build overrides the default, so
     * clear it the first time we see each chat. Telegram has no way to remove
     * the menu button entirely — this only makes it open the command list.
     */
    private void ensureMenuReset(long chatId) {
        if (!menuResetChats.add(chatId)) {
            return;
        }
        try {
            api.setChatMenuButtonCommands(chatId);
        } catch (Exception e) {
            System.err.println("Could not reset the menu button for chat " + chatId + ": " + e.getMessage());
        }
    }

    private static long chatIdOf(Map<String, Object> message) {
        return Json.num(Json.obj(message.get("chat")).get("id"));
    }
}
