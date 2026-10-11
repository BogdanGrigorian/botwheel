package com.botwheel;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal Telegram Bot API client (JDK HttpClient, no external deps).
 *
 * Only the methods the vault bot needs are implemented: getMe, getUpdates
 * (long polling), sendMessage, sendDocument, answerCallbackQuery and
 * setChatMenuButton.
 */
public final class TelegramApi {

    private final String baseUrl;
    private final HttpClient http;

    public TelegramApi(String token) {
        this.baseUrl = "https://api.telegram.org/bot" + token + "/";
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Call a Bot API method with a JSON body.
     * Returns the full decoded response ({ok, result, ...}); throws on !ok.
     */
    public Map<String, Object> call(String method, Map<String, Object> params)
            throws IOException, InterruptedException {
        String body = Json.encode(params);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + method))
                .timeout(Duration.ofSeconds(65))
                .header("Content-Type", "application/json; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> root = Json.obj(Json.parse(resp.body()));
        if (!Json.bool(root.get("ok"))) {
            throw new IOException("Telegram API " + method + " failed: " + resp.body());
        }
        return root;
    }

    /** Validate the token and return the bot's User object. */
    public Map<String, Object> getMe() throws IOException, InterruptedException {
        return call("getMe", new LinkedHashMap<>());
    }

    /** Long-poll for updates. Blocks up to timeoutSeconds (max 50) when idle. */
    public List<Object> getUpdates(long offset, int timeoutSeconds)
            throws IOException, InterruptedException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("offset", offset);
        params.put("timeout", timeoutSeconds);
        params.put("allowed_updates", List.of("message", "callback_query"));
        return Json.arr(call("getUpdates", params).get("result"));
    }

    public Map<String, Object> sendMessage(long chatId, String text, Map<String, Object> replyMarkup)
            throws IOException, InterruptedException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("chat_id", chatId);
        params.put("text", text);
        if (replyMarkup != null) {
            params.put("reply_markup", replyMarkup);
        }
        return call("sendMessage", params);
    }

    public Map<String, Object> sendMessage(long chatId, String text, Map<String, Object> replyMarkup,
            String parseMode) throws IOException, InterruptedException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("chat_id", chatId);
        params.put("text", text);
        if (replyMarkup != null) {
            params.put("reply_markup", replyMarkup);
        }
        if (parseMode != null && !parseMode.isEmpty()) {
            params.put("parse_mode", parseMode);
        }
        return call("sendMessage", params);
    }

    /** Upload a document (used for vaults that don't fit in a 4096-char message). */
    public Map<String, Object> sendDocument(long chatId, String filename, String content)
            throws IOException, InterruptedException {
        String boundary = "----tg" + System.nanoTime();
        byte[] body = multipartBody(boundary, chatId, filename, content);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "sendDocument"))
                .timeout(Duration.ofSeconds(65))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> root = Json.obj(Json.parse(resp.body()));
        if (!Json.bool(root.get("ok"))) {
            throw new IOException("Telegram API sendDocument failed: " + resp.body());
        }
        return root;
    }

    public Map<String, Object> answerCallbackQuery(String callbackQueryId, String text)
            throws IOException, InterruptedException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("callback_query_id", callbackQueryId);
        if (text != null && !text.isEmpty()) {
            params.put("text", text);
        }
        return call("answerCallbackQuery", params);
    }

    /** Host the Mini App as the default private-chat menu button. */
    public Map<String, Object> setChatMenuButtonWebApp(String label, String url)
            throws IOException, InterruptedException {
        return setChatMenuButtonWebApp(null, label, url);
    }

    /**
     * Host the Mini App as the menu button, optionally scoped to one chat
     * ({@code chatId == null} sets the default for all chats).
     */
    public Map<String, Object> setChatMenuButtonWebApp(Long chatId, String label, String url)
            throws IOException, InterruptedException {
        Map<String, Object> webApp = new LinkedHashMap<>();
        webApp.put("url", url);
        Map<String, Object> button = new LinkedHashMap<>();
        button.put("type", "web_app");
        button.put("text", label);
        button.put("web_app", webApp);
        Map<String, Object> params = new LinkedHashMap<>();
        if (chatId != null) {
            params.put("chat_id", chatId);
        }
        params.put("menu_button", button);
        return call("setChatMenuButton", params);
    }

    /** Register the bot's command list (shown in the chat's command menu). */
    public Map<String, Object> setMyCommands(List<Map<String, Object>> commands)
            throws IOException, InterruptedException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("commands", commands);
        return call("setMyCommands", params);
    }

    private static byte[] multipartBody(String boundary, long chatId, String filename, String content) {
        StringBuilder sb = new StringBuilder();
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n");
        sb.append(chatId).append("\r\n");
        sb.append("--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=\"document\"; filename=\"")
                .append(filename).append("\"\r\n");
        sb.append("Content-Type: text/plain; charset=utf-8\r\n\r\n");

        byte[] head = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] mid = content.getBytes(StandardCharsets.UTF_8);
        byte[] end = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);

        byte[] out = new byte[head.length + mid.length + end.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(mid, 0, out, head.length, mid.length);
        System.arraycopy(end, 0, out, head.length + mid.length, end.length);
        return out;
    }
}
