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
 * The bot does NO client-side encryption/decryption: it only stores the vault
 * transport string per user and hands it back over chat when the user taps
 * "Refresh database" (or sends /refresh). The user then opens the Mini App
 * (menu button / inline button) to unlock it with their password. New versions
 * produced by the Mini App are stored when the user sends /update &lt;blob&gt;.
 * The stored blob may additionally be wrapped with server-side *at-rest*
 * encryption ({@link AtRestCrypto}); that layer is transparent to the client.
 */
public final class BotwheelBot {

    private static final int MAX_MESSAGE_LENGTH = 4096;
    private static final int MAX_NOTE_LENGTH = 120;

    private final BotConfig config;
    private final TelegramApi api;
    private final VaultStore store;
    private final String seedBlob; // may be null
    private final Set<Long> menuResetChats = new HashSet<>();

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
        // vault update to store like an /update command.
        Object webAppData = message.get("web_app_data");
        if (webAppData != null) {
            String data = Json.str(Json.obj(webAppData).get("data"));
            String trimmed = data == null ? "" : data.trim();
            if (trimmed.startsWith("/refresh") || trimmed.equals("refresh")) {
                sendVault(userId, chatId);
            } else if (trimmed.startsWith("/start") || trimmed.startsWith("/help")) {
                welcome(userId, chatId);
            } else {
                storeVaultUpdate(userId, chatId, data);
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
        } else if (text.startsWith("/update")) {
            storeVaultUpdate(userId, chatId, text.substring("/update".length()));
        } else if (looksLikeVault(text)) {
            storeVaultUpdate(userId, chatId, text);
        }
        // Anything else is ignored.
    }

    private void welcome(long userId, long chatId) throws Exception {
        maybeSeed(userId);
        String text = "\uD83D\uDD10 Botwheel Vault\n\n"
                + "This bot stores your encrypted vault and hands it back to you over chat. "
                + "Tap \u201CRefresh database\u201D to receive your vault, then open the Mini App to unlock it. "
                + "When you create or edit records, the Mini App sends the new vault back here automatically.";
        api.sendMessage(chatId, text, mainKeyboard());
        api.sendMessage(chatId,
                "Use the \u201COpen Vault\u201D keyboard button below the message field to open, "
                        + "edit and save the vault \u2014 changes are sent back to me automatically.",
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
        VaultStore.Entry entry = store.get(userId);
        if (entry == null || entry.blob == null || entry.blob.isEmpty()) {
            api.sendMessage(chatId,
                    "No vault stored yet. Create it in the Mini App and send it back here "
                            + "(open the vault with the keyboard button below).",
                    updateKeyboard(userId));
            return;
        }
        String blob = entry.blob;
        // A <pre> code block: tapping it copies the whole blob in one tap.
        // Tested: wrapping it in <blockquote expandable> is accepted by the API
        // but the client drops the quote and shows a plain code block, so
        // "collapsed + copyable" can't be combined — one-click copy wins.
        String text = "\uD83D\uDD10 Your encrypted vault (v" + entry.version + ") — tap to copy:\n\n"
                + "<pre>" + blob + "</pre>";
        if (text.length() <= MAX_MESSAGE_LENGTH) {
            api.sendMessage(chatId, text, updateKeyboard(userId), "HTML");
        } else {
            api.sendMessage(chatId,
                    "Your vault is too large for a single message \u2014 sending it as a file.",
                    updateKeyboard(userId));
            api.sendDocument(chatId, "vault-v" + entry.version + ".txt", blob);
        }
    }

    private void maybeSeed(long userId) {
        if (seedBlob != null) {
            store.seedIfAbsent(userId, seedBlob);
        }
    }

    /**
     * Store a new vault version sent by the Mini App (as "/update &lt;blob&gt;"
     * or a bare transport string) and bump the user's revision.
     */
    private void storeVaultUpdate(long userId, long chatId, String raw) throws Exception {
        String blob = extractVaultBlob(raw);
        if (blob == null) {
            api.sendMessage(chatId,
                    "Send the vault string produced by the Mini App, e.g.\n/update VLT2:\u2026", null);
            return;
        }
        VaultStore.Entry current = store.get(userId);
        if (current != null && VaultStore.checksumOf(blob).equals(current.checksum)) {
            api.sendMessage(chatId,
                    "Already stored as v" + current.version + " (" + current.checksum
                            + ") \u2014 nothing to update.", null);
            return;
        }
        VaultStore.Entry entry = store.put(userId, blob);
        // The Mini App appends what it changed, so the confirmation can say so.
        String note = extractVaultNote(raw, blob);
        // Re-send the keyboard so its Mini App URL carries the new revision.
        api.sendMessage(chatId,
                "Vault updated to v" + entry.version + " (" + entry.checksum + "). "
                        + "Tap \u201CRefresh database\u201D to receive it."
                        + (note.isEmpty() ? "" : " " + note),
                updateKeyboard(userId));
    }

    /**
     * Pull the Mini App's short change description out of the update payload.
     * It rides after the blob on a new line, prefixed with "note:" (e.g.
     * "note: added new record: GitHub"); anything else is ignored. Returns ""
     * when there is no note.
     */
    private static String extractVaultNote(String raw, String blob) {
        if (raw == null || blob == null) {
            return "";
        }
        int end = raw.indexOf(blob) + blob.length();
        String rest = raw.substring(Math.min(end, raw.length())).trim();
        if (!rest.regionMatches(true, 0, "note:", 0, 5)) {
            return "";
        }
        // One short line only — it is appended to the confirmation message.
        rest = rest.substring(5).replaceAll("\\s+", " ").trim();
        if (rest.length() > MAX_NOTE_LENGTH) {
            rest = rest.substring(0, MAX_NOTE_LENGTH).trim() + "\u2026";
        }
        return rest;
    }

    /** True if the message already carries a vault transport string. */
    private static boolean looksLikeVault(String text) {
        return text.startsWith("VLT2:") || text.startsWith("VLT1:");
    }

    /**
     * Pull the transport string out of the argument, tolerating a leading
     * "/update", surrounding whitespace and trailing text. Requires an 8-hex
     * checksum suffix so obviously malformed input is rejected.
     */
    private static String extractVaultBlob(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        int at = looksLikeVault(s) ? 0 : s.indexOf("VLT2:");
        if (at < 0) {
            at = s.indexOf("VLT1:");
        }
        if (at < 0) {
            return null;
        }
        s = s.substring(at);
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) {
                s = s.substring(0, i);
                break;
            }
        }
        int dot = s.lastIndexOf('.');
        if (dot < 0 || s.length() - dot - 1 != 8 || !isHex(s.substring(dot + 1))) {
            return null;
        }
        return s;
    }

    private static boolean isHex(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static List<Map<String, Object>> commandList() {
        return List.of(
                command("start", "Show the welcome message"),
                command("refresh", "Receive your encrypted vault"),
                command("update", "Store a new vault version (from the Mini App)"));
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
