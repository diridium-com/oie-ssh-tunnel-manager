/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jcraft.jsch.JSchException;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the pure hint logic (no network). The staged JSch probing in
 * diagnose() itself is only exercised by the manual probe, not here.
 */
class JschConnectionFactoryHintsTest {

    private final JschConnectionFactory factory = new JschConnectionFactory();

    private SshTunnel keyTunnel() {
        var tunnel = Fakes.passwordTunnel(null, "vendor");
        tunnel.setAuthMethod(AuthMethod.PRIVATE_KEY);
        tunnel.setKeySource(KeySource.INLINE);
        tunnel.setPrivateKeyPem("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----");
        return tunnel;
    }

    @Test
    void authHintForKeyWhenServerOffersPublickey() {
        var e = new JSchException("Auth fail for methods 'publickey,password'");
        var hint = JschConnectionFactory.authHint(e, keyTunnel());
        assertTrue(hint.contains("authorized_keys"), hint);
        assertTrue(hint.contains("700") && hint.contains("600"), hint);
    }

    @Test
    void authHintForKeyWhenServerDoesNotOfferPublickey() {
        var e = new JSchException("Auth fail for methods 'password,keyboard-interactive'");
        var hint = JschConnectionFactory.authHint(e, keyTunnel());
        assertTrue(hint.contains("does not offer public-key"), hint);
        assertTrue(hint.contains("PubkeyAuthentication"), hint);
    }

    @Test
    void authHintForPasswordWhenServerOnlyOffersPublickey() {
        var e = new JSchException("Auth fail for methods 'publickey'");
        var hint = JschConnectionFactory.authHint(e, Fakes.passwordTunnel(null, "vendor"));
        assertTrue(hint.contains("does not offer password"), hint);
    }

    @Test
    void loopbackBindProducesNoWarningButPublicBindDoes() {
        var tunnel = Fakes.passwordTunnel(null, "vendor");
        // Default forward binds 127.0.0.1 -> no warning.
        var clean = new DiagnosticResult();
        factory.configPreChecks(clean, tunnel);
        assertTrue(clean.getSteps().stream().noneMatch(s -> s.getName().equals("Forward bind exposure")),
                "loopback bind should not warn");

        tunnel.getForwards().get(0).setBindHost("0.0.0.0");
        var warned = new DiagnosticResult();
        factory.configPreChecks(warned, tunnel);
        var step = warned.getSteps().stream()
                .filter(s -> s.getName().equals("Forward bind exposure"))
                .findFirst().orElseThrow();
        assertEquals(StepStatus.WARN, step.getStatus());
        assertTrue(step.getHint().contains("127.0.0.1"), step.getHint());
    }

    @Test
    void pastedPublicKeyWarns() {
        var tunnel = keyTunnel();
        tunnel.setPrivateKeyPem("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host");
        var result = new DiagnosticResult();
        factory.configPreChecks(result, tunnel);
        var step = result.getSteps().stream()
                .filter(s -> s.getName().equals("Private key"))
                .findFirst().orElseThrow();
        assertEquals(StepStatus.WARN, step.getStatus());
        assertTrue(step.getDetail().contains("public key"), step.getDetail());
    }

    @Test
    void encryptedLegacyPemWithoutPassphraseWarns() {
        var tunnel = keyTunnel();
        tunnel.setPrivateKeyPem("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----");
        tunnel.setPrivateKeyPassphrase("");
        var result = new DiagnosticResult();
        factory.configPreChecks(result, tunnel);
        assertTrue(result.getSteps().stream()
                .anyMatch(s -> s.getName().equals("Private key") && s.getDetail().contains("encrypted")),
                steps(result));
    }

    // Real ssh-keygen ed25519 keys: one encrypted (cipher aes256-ctr), one not (cipher none).
    private static final String ENCRYPTED_OPENSSH = String.join("\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABADp25nC+",
            "ZFgyiP2s4NwTHIAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIARgjpG7g2Hw6Lml",
            "N0yrBVsmpJwpbeEWJY9s6AM/szyIAAAAoJbJSgTR45SnQbvzRxilxi/dLTBIMR8gf37Ks3",
            "2R39JvHbqvqYW4NJGdRmWZ/wXUV45uBmdfZRdevToOdOW+TFN/RsYHKtrrRU1gX9AgdmOI",
            "HuikBrr+U/SzJlYVBZkYdQeY8bGJvfGrYM4bK4E2dggiptpw8jIUWn4BPehMfQ+Wgf1Whu",
            "xg9nyKmbhS9tujO+kuQIIThy0p/xIhjrkdEkw=",
            "-----END OPENSSH PRIVATE KEY-----");

    private static final String PLAIN_OPENSSH = String.join("\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
            "QyNTUxOQAAACDEwOlWyKOG5BbRAQRRNtbziJnJL33428WHXNvUEoAyXAAAAKA7DDFcOwwx",
            "XAAAAAtzc2gtZWQyNTUxOQAAACDEwOlWyKOG5BbRAQRRNtbziJnJL33428WHXNvUEoAyXA",
            "AAAEBn0iQp8YHcJOPXgLiTJRqXyzLZjjX9dg1tiZyZmZ8IJsTA6VbIo4bkFtEBBFE21vOI",
            "mckvffjbxYdc29QSgDJcAAAAHXBjb3luZUBQYXVscy1NYWMtbWluaS0yLmxvY2Fs",
            "-----END OPENSSH PRIVATE KEY-----");

    @Test
    void detectsEncryptedOpenSshKeyByCipherField() {
        assertTrue(JschConnectionFactory.looksEncryptedOpenSsh(ENCRYPTED_OPENSSH),
                "aes256-ctr OpenSSH key should read as encrypted");
        assertTrue(!JschConnectionFactory.looksEncryptedOpenSsh(PLAIN_OPENSSH),
                "cipher=none OpenSSH key should not read as encrypted");
        assertTrue(!JschConnectionFactory.looksEncryptedOpenSsh("not a key"));
    }

    @Test
    void encryptedOpenSshKeyWithoutPassphraseWarns() {
        // The modern default format has no ENCRYPTED/Proc-Type markers in the armor.
        var tunnel = keyTunnel();
        tunnel.setPrivateKeyPem(ENCRYPTED_OPENSSH);
        tunnel.setPrivateKeyPassphrase("");
        var result = new DiagnosticResult();
        factory.configPreChecks(result, tunnel);
        assertTrue(result.getSteps().stream()
                .anyMatch(s -> s.getName().equals("Private key") && s.getDetail().contains("encrypted")),
                steps(result));
    }

    @Test
    void plainOpenSshKeyWithoutPassphraseDoesNotWarn() {
        var tunnel = keyTunnel();
        tunnel.setPrivateKeyPem(PLAIN_OPENSSH);
        tunnel.setPrivateKeyPassphrase("");
        var result = new DiagnosticResult();
        factory.configPreChecks(result, tunnel);
        assertTrue(result.getSteps().stream().noneMatch(s -> s.getName().equals("Private key")),
                "an unencrypted key must not warn: " + steps(result));
    }

    private static String steps(DiagnosticResult result) {
        return result.getSteps().stream().map(DiagnosticStep::toString).collect(java.util.stream.Collectors.joining("; "));
    }
}
