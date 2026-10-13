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
import java.util.ArrayList;
import java.util.List;

/**
 * File-backed, per-user record storage with simple versioning, implemented on
 * top of an embedded H2 database.
 *
 * H2 is pure Java (no native libraries), so it runs unchanged in the slim
 * {@code eclipse-temurin} JRE image and works the same on Windows and Linux.
 * The database is a single file, e.g. {@code botwheel-db.mv.db}.
 *
 * The bot never inspects record contents — it stores each record's opaque
 * ciphertext and the small vault header (KDF params + salt) that lets the Mini
 * App derive the key. One row per record means a change only has to send that
 * one record over chat, so an update always fits in a single message; the
 * refresh path reassembles the whole container from the rows.
 *
 * Tables:
 *   {@code vault_meta} — one row per user: the header, the monotonic
 *                       {@code version} and the created/updated timestamps.
 *   {@code records}    — one row per record: {@code (user_id, record_id)} plus
 *                       the opaque {@code r1.…} ciphertext.
 *
 * When constructed with an {@link AtRestCrypto}, the header and every
 * ciphertext are SERVER-ENCRYPTED ({@code SRV1.…}) before they are written and
 * decrypted transparently on read.
 */
public final class VaultStore implements AutoCloseable {

    /** One change to a user's record set: a delete, or an add/replace. */
    public static final class Op {
        public final boolean delete;
        public final String id;
        public final String cipher; // null for a delete

        private Op(boolean delete, String id, String cipher) {
            this.delete = delete;
            this.id = id;
            this.cipher = cipher;
        }

        public static Op add(String id, String cipher) {
            return new Op(false, id, cipher);
        }

        public static Op delete(String id) {
            return new Op(true, id, null);
        }
    }

    /** A user's whole vault: the header, the rows and the revision metadata. */
    public static final class Snapshot {
        public final String header; // base64url(kdfHeader || salt)
        public final long version;
        public final long createdAtMillis;
        public final long updatedAtMillis;
        public final List<CryptoCore.StoredRecord> records;

        Snapshot(String header, long version, long createdAtMillis, long updatedAtMillis,
                List<CryptoCore.StoredRecord> records) {
            this.header = header;
            this.version = version;
            this.createdAtMillis = createdAtMillis;
            this.updatedAtMillis = updatedAtMillis;
            this.records = records;
        }

        /** Number of stored records. */
        public int size() {
            return records.size();
        }
    }

    /** Unchecked wrapper so store methods keep their existing signatures. */
    public static final class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final String CREATE_META = """
            CREATE TABLE IF NOT EXISTS vault_meta (
                user_id     BIGINT  PRIMARY KEY,
                header      CLOB    NOT NULL,
                version     BIGINT  NOT NULL,
                created_at  BIGINT  NOT NULL,
                updated_at  BIGINT  NOT NULL
            )
            """;

    private static final String CREATE_RECORDS = """
            CREATE TABLE IF NOT EXISTS records (
                user_id     BIGINT      NOT NULL,
                record_id   VARCHAR(64) NOT NULL,
                cipher      CLOB        NOT NULL,
                updated_at  BIGINT      NOT NULL,
                PRIMARY KEY (user_id, record_id)
            )
            """;

    private static final String MERGE_META = """
            MERGE INTO vault_meta (user_id, header, version, created_at, updated_at)
            KEY (user_id)
            VALUES (?, ?, ?, ?, ?)
            """;

    private static final String MERGE_RECORD = """
            MERGE INTO records (user_id, record_id, cipher, updated_at)
            KEY (user_id, record_id)
            VALUES (?, ?, ?, ?)
            """;

    private static final String DELETE_RECORD =
            "DELETE FROM records WHERE user_id = ? AND record_id = ?";

    private static final String SELECT_META =
            "SELECT header, version, created_at, updated_at FROM vault_meta WHERE user_id = ?";

    private static final String SELECT_RECORDS =
            "SELECT record_id, cipher FROM records WHERE user_id = ? ORDER BY record_id";

    private final Connection conn;
    private final AtRestCrypto atRest; // nullable — null means store values as-is

    /**
     * Open (creating if absent) the database at {@code dbPath} WITHOUT at-rest
     * encryption. The path may be a filesystem location ({@code /data/botwheel})
     * or a full H2 JDBC URL ({@code jdbc:h2:mem:test}).
     */
    public VaultStore(String dbPath) {
        this(dbPath, null);
    }

    /**
     * Open the database, optionally wrapping every stored value with the given
     * server-side at-rest cipher. Pass {@code null} to store values as-is.
     */
    public VaultStore(String dbPath, AtRestCrypto atRest) {
        this.atRest = atRest;
        this.conn = open(dbPath);
        try (Statement st = conn.createStatement()) {
            st.execute(CREATE_META);
            st.execute(CREATE_RECORDS);
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

    /** The user's whole vault, or null when nothing is stored yet. */
    public synchronized Snapshot snapshot(long userId) {
        String header;
        long version;
        long createdAt;
        long updatedAt;
        try (PreparedStatement ps = conn.prepareStatement(SELECT_META)) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                String storedHeader = rs.getString("header");
                header = atRest == null ? storedHeader : atRest.decrypt(storedHeader);
                version = rs.getLong("version");
                createdAt = rs.getLong("created_at");
                updatedAt = rs.getLong("updated_at");
            }
        } catch (SQLException e) {
            throw new StorageException("Could not read vault for user " + userId, e);
        }

        List<CryptoCore.StoredRecord> records = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(SELECT_RECORDS)) {
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String stored = rs.getString("cipher");
                    records.add(new CryptoCore.StoredRecord(rs.getString("record_id"),
                            atRest == null ? stored : atRest.decrypt(stored)));
                }
            }
        } catch (SQLException e) {
            throw new StorageException("Could not read records for user " + userId, e);
        }
        return new Snapshot(header, version, createdAt, updatedAt, records);
    }

    /**
     * Apply record changes (adds / deletes) and bump the version. The header is
     * stored on the first write and kept afterwards, so every record keeps
     * decrypting with the same key.
     */
    public synchronized Snapshot applyOps(long userId, String headerB64, List<Op> ops) {
        long now = System.currentTimeMillis();
        try {
            conn.setAutoCommit(false);

            String metaHeader = null;
            long version = 1;
            long createdAt = now;
            try (PreparedStatement ps = conn.prepareStatement(SELECT_META)) {
                ps.setLong(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String storedHeader = rs.getString("header");
                        metaHeader = atRest == null ? storedHeader : atRest.decrypt(storedHeader);
                        version = rs.getLong("version") + 1;
                        createdAt = rs.getLong("created_at");
                    }
                }
            }
            if (metaHeader == null) {
                metaHeader = headerB64 == null ? "" : headerB64;
            }

            try (PreparedStatement ps = conn.prepareStatement(MERGE_META)) {
                ps.setLong(1, userId);
                ps.setString(2, wrap(metaHeader));
                ps.setLong(3, version);
                ps.setLong(4, createdAt);
                ps.setLong(5, now);
                ps.executeUpdate();
            }

            for (Op op : ops) {
                if (op.delete) {
                    try (PreparedStatement ps = conn.prepareStatement(DELETE_RECORD)) {
                        ps.setLong(1, userId);
                        ps.setString(2, op.id);
                        ps.executeUpdate();
                    }
                } else {
                    try (PreparedStatement ps = conn.prepareStatement(MERGE_RECORD)) {
                        ps.setLong(1, userId);
                        ps.setString(2, op.id);
                        ps.setString(3, wrap(op.cipher));
                        ps.setLong(4, now);
                        ps.executeUpdate();
                    }
                }
            }
            conn.commit();
        } catch (SQLException e) {
            rollbackQuietly();
            throw new StorageException("Could not apply record changes for user " + userId, e);
        } finally {
            try {
                conn.setAutoCommit(true);
            } catch (SQLException ignored) {
                // nothing sensible to do here
            }
        }
        return snapshot(userId);
    }

    /** Seed a user's vault only if none exists yet (an imported container). */
    public synchronized Snapshot seedIfAbsent(long userId, String headerB64,
            List<CryptoCore.StoredRecord> records) {
        Snapshot existing = snapshot(userId);
        if (existing != null) {
            return existing;
        }
        List<Op> ops = new ArrayList<>();
        for (CryptoCore.StoredRecord record : records) {
            ops.add(Op.add(record.id, record.cipher));
        }
        return applyOps(userId, headerB64, ops);
    }

    /** Wrap a stored value with the at-rest cipher when one is configured. */
    private String wrap(String value) {
        return atRest == null ? value : atRest.encrypt(value);
    }

    private void rollbackQuietly() {
        try {
            conn.rollback();
        } catch (SQLException ignored) {
            // the original failure is more interesting than this one
        }
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
