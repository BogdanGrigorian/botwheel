package com.botwheel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The Mini App's per-record update payload (wire format {@code VUP1:}).
 *
 * <pre>
 * VUP1:&lt;headerB64&gt;
 * add:&lt;id&gt;:&lt;r1.cipher&gt;
 * del:&lt;id&gt;
 * note: &lt;short change description&gt;      (optional, last line)
 * </pre>
 *
 * One message carries one or two ops - an edit is a delete of the old content id
 * plus an add of the new one - so it always stays far below Telegram's
 * 4096-character message limit. The note is plain text the bot only echoes back
 * in its confirmation; it is never stored.
 */
public final class UpdatePayload {

    private static final int MAX_NOTE_LENGTH = 120;

    /** The vault header (base64url), needed to store the salt on the first write. */
    public final String headerB64;
    /** The record changes, in the order the Mini App produced them. */
    public final List<VaultStore.Op> ops;
    /** A short plain-text description of the change ("" when absent). */
    public final String note;

    private UpdatePayload(String headerB64, List<VaultStore.Op> ops, String note) {
        this.headerB64 = headerB64;
        this.ops = Collections.unmodifiableList(ops);
        this.note = note;
    }

    /**
     * Parse a payload, tolerating a leading {@code /update} and surrounding
     * whitespace. Returns {@code null} when the text is not a recognised payload
     * or carries no valid op.
     */
    public static UpdatePayload parse(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        if (s.startsWith("/update")) {
            s = s.substring("/update".length()).trim();
        }
        if (!s.startsWith(CryptoCore.OP_PREFIX)) {
            return null;
        }
        String[] lines = s.split("\r?\n");
        String header = lines[0].substring(CryptoCore.OP_PREFIX.length()).trim();
        if (header.isEmpty()) {
            return null;
        }
        List<VaultStore.Op> ops = new ArrayList<>();
        String note = "";
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }
            if (line.regionMatches(true, 0, "note:", 0, 5)) {
                note = collapse(line.substring(5), MAX_NOTE_LENGTH);
                break; // the note is always the last line
            }
            if (line.startsWith("add:")) {
                String rest = line.substring("add:".length());
                int colon = rest.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String id = rest.substring(0, colon);
                String cipher = rest.substring(colon + 1).trim();
                if (isRecordId(id) && cipher.startsWith(CryptoCore.RECORD_PREFIX)) {
                    ops.add(VaultStore.Op.add(id, cipher));
                }
            } else if (line.startsWith("del:")) {
                String id = line.substring("del:".length()).trim();
                if (isRecordId(id)) {
                    ops.add(VaultStore.Op.delete(id));
                }
            }
        }
        return ops.isEmpty() ? null : new UpdatePayload(header, ops, note);
    }

    /** Collapse whitespace and cap the length of the one-line description. */
    private static String collapse(String text, int max) {
        String s = text.replaceAll("\\s+", " ").trim();
        if (s.length() > max) {
            s = s.substring(0, max).trim() + "\u2026";
        }
        return s;
    }

    /** A record id is 16 lower-case hex characters (the record's content hash). */
    public static boolean isRecordId(String s) {
        if (s == null || s.length() != CryptoCore.RECORD_ID_HEX) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) {
                return false;
            }
        }
        return true;
    }
}
