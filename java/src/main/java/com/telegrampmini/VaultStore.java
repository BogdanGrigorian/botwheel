package com.telegrampmini;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory, per-user vault storage with simple versioning.
 *
 * The bot never decrypts or inspects the blob — it only stores the opaque
 * transport string and hands it back over chat.
 *
 * Persistence is intentionally out of scope for now: everything lives in RAM
 * and is lost on restart. The upload path (Mini App -> bot) will call
 * {@link #put(long, String)}; the refresh path calls {@link #get(long)}.
 */
public final class VaultStore {

    /** A stored vault snapshot. */
    public static final class Entry {
        public final String blob;
        public final long version;
        public final long updatedAtMillis;

        Entry(String blob, long version, long updatedAtMillis) {
            this.blob = blob;
            this.version = version;
            this.updatedAtMillis = updatedAtMillis;
        }
    }

    private final ConcurrentHashMap<Long, Entry> vaults = new ConcurrentHashMap<>();

    /** Store a new version of a user's vault (bumps the version). */
    public Entry put(long userId, String blob) {
        Entry prev = vaults.get(userId);
        long version = prev == null ? 1 : prev.version + 1;
        Entry entry = new Entry(blob, version, System.currentTimeMillis());
        vaults.put(userId, entry);
        return entry;
    }

    /** Current vault for a user, or null if none is stored. */
    public Entry get(long userId) {
        return vaults.get(userId);
    }

    /** Seed a user's vault only if none exists yet (demo blob, version 1). */
    public Entry seedIfAbsent(long userId, String blob) {
        return vaults.computeIfAbsent(userId, id -> new Entry(blob, 1, System.currentTimeMillis()));
    }
}
