package com.botwheel;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Server-side "at rest" encryption for the stored vault blob.
 *
 * The bot keeps each vault encrypted inside its embedded database under a key
 * that lives OUTSIDE the database (an env-provided secret or a key file). It
 * decrypts a vault only to hand the string back to its owner over chat.
 *
 * This protects the database file if it is stolen (backups, disk snapshots,
 * read-only DB access): the key is a SEPARATE asset, so for real separation it
 * must not be stored next to the database. It does NOT protect against a
 * compromised running process, and it is not a substitute for the user's own
 * client-side encryption.
 *
 * Wire format: {@code SRV1.<base64url(iv || ciphertext || tag)>}. Legacy
 * plaintext rows (no {@code SRV1.} prefix) are passed through unchanged, so an
 * existing database keeps working and migrates row by row on the next write.
 */
public final class AtRestCrypto {

    /** Marks an encrypted stored value; anything else is treated as legacy plaintext. */
    public static final String PREFIX = "SRV1.";

    /** Config value that explicitly disables at-rest encryption. */
    public static final String DISABLED = "off";

    private static final int KEY_BYTES = 32; // AES-256
    private static final int IV_BYTES = 12;  // GCM nonce
    private static final int TAG_BITS = 128;

    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();

    private final SecretKey key;
    private final SecureRandom rng = new SecureRandom();

    private AtRestCrypto(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Resolve the at-rest key from, in order: a base64 {@code keyBase64} string,
     * an existing key file, or a freshly generated key persisted to the key
     * file. Returns {@code null} when neither is configured (the caller then
     * runs without server-side encryption).
     *
     * @param keyBase64 base64 of a 32-byte key, or null/blank
     * @param keyFile   path to the key file (created if missing), or null/blank
     * @param log       sink for one-line status messages (never the key itself)
     */
    public static AtRestCrypto resolve(String keyBase64, String keyFile, PrintStream log) {
        if (keyBase64 != null && !keyBase64.isBlank()) {
            log.println("At-rest encryption: ON (key from configuration)");
            return new AtRestCrypto(decodeKey(keyBase64.trim()));
        }

        String trimmed = keyFile == null ? "" : keyFile.trim();
        if (trimmed.isEmpty() || DISABLED.equalsIgnoreCase(trimmed)) {
            log.println("At-rest encryption: OFF — set telegram.db.key or telegram.db.key.file to enable.");
            return null;
        }

        Path path = Paths.get(trimmed);
        try {
            if (Files.isRegularFile(path)) {
                log.println("At-rest encryption: ON (key file " + path.toAbsolutePath() + ")");
                return new AtRestCrypto(decodeKey(Files.readString(path, StandardCharsets.UTF_8).trim()));
            }
            byte[] kb = new byte[KEY_BYTES];
            rngFor(kb);
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(path, Base64.getEncoder().encodeToString(kb), StandardCharsets.UTF_8);
            log.println("At-rest encryption: ON (generated new key file " + path.toAbsolutePath()
                    + ")\n  Back it up and keep it OUTSIDE the database volume — losing it bricks every vault.");
            return new AtRestCrypto(kb);
        } catch (IOException e) {
            throw new VaultStore.StorageException("Could not read or create at-rest key file " + path, e);
        }
    }

    private static void rngFor(byte[] bytes) {
        new SecureRandom().nextBytes(bytes);
    }

    private static byte[] decodeKey(String base64) {
        byte[] kb;
        try {
            kb = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new VaultStore.StorageException("At-rest key is not valid base64", e);
        }
        if (kb.length != KEY_BYTES) {
            throw new VaultStore.StorageException(
                    "At-rest key must be " + KEY_BYTES + " bytes (got " + kb.length + ")", null);
        }
        return kb;
    }

    /** True if {@code stored} already carries the encryption prefix. */
    public static boolean isEncrypted(String stored) {
        return stored != null && stored.startsWith(PREFIX);
    }

    /** Encrypt a plaintext vault transport string for storage. */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_BYTES];
            rng.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX + ENC.encodeToString(concat(iv, ct));
        } catch (Exception e) {
            throw new VaultStore.StorageException("Could not encrypt vault for storage", e);
        }
    }

    /** Decrypt a stored value. Legacy plaintext (no prefix) is returned as-is. */
    public String decrypt(String stored) {
        if (stored == null || !isEncrypted(stored)) {
            return stored; // legacy plaintext row — pass through
        }
        try {
            byte[] raw = DEC.decode(stored.substring(PREFIX.length()));
            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(raw, 0, iv, 0, IV_BYTES);
            byte[] ct = new byte[raw.length - IV_BYTES];
            System.arraycopy(raw, IV_BYTES, ct, 0, ct.length);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new VaultStore.StorageException(
                    "Could not decrypt stored vault — wrong or missing at-rest key?", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
