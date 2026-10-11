package com.botwheel;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * File-backed, per-user vault storage with simple versioning, implemented on
 * top of an embedded H2 database.
 *
 * H2 is pure Java (no native libraries), so it runs unchanged in the slim
 * {@code eclipse-temurin} JRE image and works the same on Windows and Linux.
 * The database is a single file, e.g. {@code botwheel-db.mv.db}.
 *
 * The bot never inspects the vault contents — it only stores the opaque
 * transport string and hands it back over chat. Besides the blob each row
 * keeps metadata: the monotonic {@code version}, the format tag, the 8-hex
 * checksum and the created/updated timestamps. The upload path (Mini App ->
 * bot) will call {@link #put(long, String)}; the refresh path calls
 * {@link #get(long)}.
 *
 * When constructed with an {@link AtRestCrypto}, the {@code blob} column holds
 * SERVER-ENCRYPTED ciphertext ({@code SRV1.…}); the metadata is still computed
 * from the plaintext transport string so the Mini App's revision stamp stays
 * consistent. Legacy plaintext rows are read transparently and re-encrypted on
 * the next write.
 */
public final class VaultStore implements AutoCloseable {

    /** A stored vault snapshot. */
    public static final class Entry {
        public final String blob;
        public final long version;
        public final long createdAtMillis;
        public final long updatedAtMillis;
        public final String format;
        public final String checksum;
        public final int blobLength;

        Entry(String blob, long version, long createdAtMillis, long updatedAtMillis,
                String format, String checksum, int blobLength) {
            this.blob = blob;
            this.version = version;
            this.createdAtMillis = createdAtMillis;
            this.updatedAtMillis = updatedAtMillis;
            this.format = format;
            this.checksum = checksum;
            this.blobLength = blobLength;
        }
    }

    /** Unchecked wrapper so store methods keep their existing signatures. */
    public static final class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final String CREATE_TABLE = """
            CREATE TABLE IF NOT EXISTS vaults (
                user_id     BIGINT       PRIMARY KEY,
                blob        CLOB         NOT NULL,
                version     BIGINT       NOT NULL,
                format      VARCHAR(16)  NOT NULL,
                checksum    VARCHAR(16),
                blob_length INTEGER      NOT NULL,
                created_at  BIGINT       NOT NULL,
                updated_at  BIGINT       NOT NULL
            )
            """;

    private static final String MERGE = """
            MERGE INTO vaults
                (user_id, blob, version, format, checksum, blob_length, created_at, updated_at)
            KEY (user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String SELECT_BY_USER = """
            SELECT blob, version, format, checksum, blob_length, created_at, updated_at
            FROM vaults
            WHERE user_id = ?
            """;

    private final Connection conn;
    private final AtRestCrypto atRest; // nullable — null means store the blob as-is

    /**
     * Open (creating if absent) the database at {@code dbPath} WITHOUT at-rest
     * encryption. The path may be a filesystem location ({@code /data/botwheel})
     * or a full H2 JDBC URL ({@code jdbc:h2:mem:test}).
     */
    public VaultStore(String dbPath) {
        this(dbPath, null);
    }

    /**
     * Open the database, optionally wrapping every stored blob with the given
     * server-side at-rest cipher. Pass {@code null} to store blobs as-is.
     */
    public VaultStore(String dbPath, AtRestCrypto atRest) {
        this.atRest = atRest;
        this.conn = open(dbPath);
        try (Statement st = conn.createStatement()) {
            st.execute(CREATE_TABLE);
        } catch (SQLException e) {
            throw new StorageException("Could not initialise vault schema", e);
        }
    }

    private static Connection open(String dbPath) {
        String url = toJdbcUrl(dbPath);
        try {
            return DriverManager.getConnection(url);
        } catch (SQLException e) {
            throw new StorageException("Could not open vault database at " + url, e);
        }
    }

    /** Build the H2 JDBC URL, creating the file's parent directory if needed. */
    private static String toJdbcUrl(String dbPath) {
        String path = dbPath == null ? "" : dbPath.trim();
        if (path.isEmpty()) {
            path = "botwheel-db";
        }
        if (path.startsWith("jdbc:h2:")) {
            return path; // explicit URL (e.g. an in-memory test database)
        }
        try {
            // H2 2.x rejects paths that are only implicitly relative to the
            // working directory, so resolve to an absolute, forward-slash path.
            Path abs = Paths.get(path).toAbsolutePath().normalize();
            Path parent = abs.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            return "jdbc:h2:" + abs.toString().replace('\\', '/');
        } catch (Exception e) {
            throw new StorageException("Could not create database directory for " + path, e);
        }
    }

    /** Store a new version of a user's vault (bumps the version). */
    public synchronized Entry put(long userId, String blob) {
        return upsert(userId, blob);
    }

    /** Seed a user's vault only if none exists yet (demo blob, version 1). */
    public synchronized Entry seedIfAbsent(long userId, String blob) {
        Entry existing = get(userId);
        return existing != null ? existing : upsert(userId, blob);
    }

    /** Current vault for a user, or null if none is stored. */
    public synchronized Entry get(long userId) {
        try (PreparedStatement ps = conn.prepareStatement(SELECT_BY_USER)) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                String stored = rs.getString("blob");
                String blob = atRest == null ? stored : atRest.decrypt(stored);
                return new Entry(
                        blob,
                        rs.getLong("version"),
                        rs.getLong("created_at"),
                        rs.getLong("updated_at"),
                        rs.getString("format"),
                        rs.getString("checksum"),
                        rs.getInt("blob_length"));
            }
        } catch (SQLException e) {
            throw new StorageException("Could not read vault for user " + userId, e);
        }
    }

    private Entry upsert(long userId, String blob) {
        Entry prev = get(userId);
        long now = System.currentTimeMillis();
        long version = prev == null ? 1 : prev.version + 1;
        long createdAt = prev == null ? now : prev.createdAtMillis;
        String format = formatOf(blob);
        String checksum = checksumOf(blob);
        int length = blob == null ? 0 : blob.length();
        // Metadata is derived from the plaintext transport string; only the
        // stored blob column is wrapped with the server-side at-rest cipher.
        String stored = atRest == null ? blob : atRest.encrypt(blob);

        try (PreparedStatement ps = conn.prepareStatement(MERGE)) {
            ps.setLong(1, userId);
            ps.setString(2, stored);
            ps.setLong(3, version);
            ps.setString(4, format);
            ps.setString(5, checksum);
            ps.setInt(6, length);
            ps.setLong(7, createdAt);
            ps.setLong(8, now);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Could not store vault for user " + userId, e);
        }
        return new Entry(blob, version, createdAt, now, format, checksum, length);
    }

    /** The 8-hex checksum embedded in the "VLT2:...<checksum>" transport string. */
    public static String checksumOf(String blob) {
        if (blob == null) {
            return "";
        }
        int dot = blob.lastIndexOf('.');
        return dot == -1 ? "" : blob.substring(dot + 1);
    }

    /** The transport format tag, e.g. "VLT1" from "VLT1:<payload>.<checksum>". */
    public static String formatOf(String blob) {
        if (blob == null) {
            return "";
        }
        int colon = blob.indexOf(':');
        return colon == -1 ? "" : blob.substring(0, colon);
    }

    @Override
    public synchronized void close() {
        try {
            conn.close();
        } catch (SQLException e) {
            throw new StorageException("Could not close vault database", e);
        }
    }
}
