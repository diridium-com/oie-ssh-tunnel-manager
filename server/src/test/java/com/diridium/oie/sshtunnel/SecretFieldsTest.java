/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.UnaryOperator;

import org.junit.jupiter.api.Test;

class SecretFieldsTest {

    private static final UnaryOperator<String> ENC = v -> "ENC[" + v + "]";
    private static final UnaryOperator<String> DEC = v -> v; // paired with values already stripped

    @Test
    void maskReplacesNonEmptySecretsOnly() {
        var tunnel = Fakes.passwordTunnel("t1", "vendor");
        tunnel.setPassword("hunter2");
        tunnel.setPrivateKeyPem("");
        tunnel.setPrivateKeyPassphrase("");

        var masked = SecretFields.mask(tunnel);

        assertEquals(SshTunnel.SECRET_MASK, masked.getPassword());
        assertEquals("", masked.getPrivateKeyPem());
        assertEquals("", masked.getPrivateKeyPassphrase());
        // Non-secret fields untouched.
        assertEquals("vendor", masked.getName());
        assertEquals("mirth", masked.getUsername());
    }

    @Test
    void resolveMasksKeepsStoredSecretWhenMasked() {
        var stored = Fakes.passwordTunnel("t1", "vendor");
        stored.setPassword("original");

        var incoming = stored.copy();
        incoming.setPassword(SshTunnel.SECRET_MASK);

        var resolved = SecretFields.resolveMasks(incoming, stored);
        assertEquals("original", resolved.getPassword());
    }

    @Test
    void resolveMasksAcceptsNewSecretWhenChanged() {
        var stored = Fakes.passwordTunnel("t1", "vendor");
        stored.setPassword("original");

        var incoming = stored.copy();
        incoming.setPassword("rotated");

        var resolved = SecretFields.resolveMasks(incoming, stored);
        assertEquals("rotated", resolved.getPassword());
    }

    @Test
    void resolveMasksOnCreateTreatsMaskAsEmpty() {
        var incoming = Fakes.passwordTunnel("t1", "vendor");
        incoming.setPassword(SshTunnel.SECRET_MASK);

        var resolved = SecretFields.resolveMasks(incoming, null);
        assertEquals("", resolved.getPassword());
    }

    @Test
    void encryptDecryptRoundTrips() {
        var tunnel = Fakes.passwordTunnel("t1", "vendor");
        tunnel.setPassword("plaintext-pw");
        tunnel.setPrivateKeyPem("-----BEGIN KEY-----");
        tunnel.setPrivateKeyPassphrase("phrase");

        var encrypted = SecretFields.encrypt(tunnel, ENC);
        assertTrue(encrypted.getPassword().startsWith(SecretFields.ENC_PREFIX));
        assertTrue(encrypted.getPassword().contains("ENC[plaintext-pw]"));

        var decrypted = SecretFields.decrypt(encrypted, v -> v.substring(4, v.length() - 1));
        assertEquals("plaintext-pw", decrypted.getPassword());
        assertEquals("-----BEGIN KEY-----", decrypted.getPrivateKeyPem());
        assertEquals("phrase", decrypted.getPrivateKeyPassphrase());
    }

    @Test
    void plaintextBeginningWithMarkerIsStillEncrypted() {
        // A user's real secret can legitimately start with the "{enc}" text.
        // It is still plaintext in memory and must be encrypted, not persisted
        // in the clear on the assumption that the prefix means ciphertext.
        var tunnel = Fakes.passwordTunnel("t1", "vendor");
        tunnel.setPassword(SecretFields.ENC_PREFIX + "p@ss");

        var encrypted = SecretFields.encrypt(tunnel, ENC);
        assertTrue(encrypted.getPassword().startsWith(SecretFields.ENC_PREFIX));
        assertEquals(SecretFields.ENC_PREFIX + "ENC[{enc}p@ss]", encrypted.getPassword());

        // And it round-trips back to the original plaintext.
        var decrypted = SecretFields.decrypt(encrypted, v -> v.substring(4, v.length() - 1));
        assertEquals(SecretFields.ENC_PREFIX + "p@ss", decrypted.getPassword());
    }

    @Test
    void decryptFailureYieldsEmptyNotCorruptBlob() {
        var tunnel = Fakes.passwordTunnel("t1", "vendor");
        tunnel.setPassword(SecretFields.ENC_PREFIX + "garbage");

        var decrypted = SecretFields.decrypt(tunnel, v -> {
            throw new RuntimeException("bad key");
        });
        // Must not leak the {enc} blob back, which would then be re-persisted as-is.
        assertEquals("", decrypted.getPassword());
    }

    @Test
    void decryptLeavesPlaintextUntouched() {
        var tunnel = Fakes.passwordTunnel("t1", "vendor");
        tunnel.setPassword("not-encrypted");

        var decrypted = SecretFields.decrypt(tunnel, DEC);
        assertEquals("not-encrypted", decrypted.getPassword());
    }
}
