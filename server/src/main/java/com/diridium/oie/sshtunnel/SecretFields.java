/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.function.UnaryOperator;

/**
 * Handling of the three secret fields on {@link SshTunnel}: password, inline
 * private key, and key passphrase.
 *
 * At rest each secret is stored with an {@code {enc}} prefix followed by the
 * engine-encrypted value. On the wire to the client each non-empty secret is
 * replaced by {@link SshTunnel#SECRET_MASK}; a client sending the mask back
 * means "keep the stored value".
 */
public final class SecretFields {

    static final String ENC_PREFIX = "{enc}";

    /** Returns a copy safe to send to the client: non-empty secrets replaced by the mask. */
    public static SshTunnel mask(SshTunnel tunnel) {
        var copy = tunnel.copy();
        copy.setPassword(maskValue(copy.getPassword()));
        copy.setPrivateKeyPem(maskValue(copy.getPrivateKeyPem()));
        copy.setPrivateKeyPassphrase(maskValue(copy.getPrivateKeyPassphrase()));
        return copy;
    }

    /**
     * Returns a copy of {@code incoming} with masked secrets replaced by the
     * stored tunnel's values. A null {@code stored} (create) resolves masks to
     * empty.
     */
    public static SshTunnel resolveMasks(SshTunnel incoming, SshTunnel stored) {
        var copy = incoming.copy();
        copy.setPassword(resolveValue(copy.getPassword(), stored != null ? stored.getPassword() : ""));
        copy.setPrivateKeyPem(resolveValue(copy.getPrivateKeyPem(), stored != null ? stored.getPrivateKeyPem() : ""));
        copy.setPrivateKeyPassphrase(resolveValue(copy.getPrivateKeyPassphrase(),
                stored != null ? stored.getPrivateKeyPassphrase() : ""));
        return copy;
    }

    /** Returns a copy with plaintext secrets encrypted for persistence. */
    public static SshTunnel encrypt(SshTunnel tunnel, UnaryOperator<String> encryptor) {
        var copy = tunnel.copy();
        copy.setPassword(encryptValue(copy.getPassword(), encryptor));
        copy.setPrivateKeyPem(encryptValue(copy.getPrivateKeyPem(), encryptor));
        copy.setPrivateKeyPassphrase(encryptValue(copy.getPrivateKeyPassphrase(), encryptor));
        return copy;
    }

    /** Returns a copy with persisted secrets decrypted for runtime use. */
    public static SshTunnel decrypt(SshTunnel tunnel, UnaryOperator<String> decryptor) {
        var copy = tunnel.copy();
        copy.setPassword(decryptValue(copy.getPassword(), decryptor));
        copy.setPrivateKeyPem(decryptValue(copy.getPrivateKeyPem(), decryptor));
        copy.setPrivateKeyPassphrase(decryptValue(copy.getPrivateKeyPassphrase(), decryptor));
        return copy;
    }

    private static String maskValue(String value) {
        return value == null || value.isEmpty() ? "" : SshTunnel.SECRET_MASK;
    }

    private static String resolveValue(String incoming, String stored) {
        if (SshTunnel.SECRET_MASK.equals(incoming)) {
            return stored != null ? stored : "";
        }
        return incoming != null ? incoming : "";
    }

    private static String encryptValue(String value, UnaryOperator<String> encryptor) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        // Always encrypt. The in-memory tunnel list holds only plaintext
        // (load() decrypts, resolveMasks passes client input through verbatim),
        // so a value that happens to start with the {enc} marker is still
        // plaintext. Skipping it here would persist that secret in the clear and
        // then lose it on the next decrypt.
        return ENC_PREFIX + encryptor.apply(value);
    }

    private static String decryptValue(String value, UnaryOperator<String> decryptor) {
        if (value == null) {
            return "";
        }
        if (!value.startsWith(ENC_PREFIX)) {
            return value;
        }
        try {
            return decryptor.apply(value.substring(ENC_PREFIX.length()));
        } catch (Exception e) {
            // Returning the raw {enc} blob would corrupt the round-trip: encrypt()
            // skips prefixed values, so the blob would persist as-is and the real
            // secret is unrecoverable anyway. Empty forces a re-enter.
            return "";
        }
    }

    private SecretFields() {
    }
}
