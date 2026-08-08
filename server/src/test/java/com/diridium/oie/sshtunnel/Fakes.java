/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test doubles that let the manager and service run with no real SSH and no
 * engine singletons.
 */
final class Fakes {

    private Fakes() {
    }

    static final class FakeSshConnection implements SshConnection {
        volatile boolean connected = true;
        volatile boolean closed;

        @Override
        public boolean isConnected() {
            return connected;
        }

        @Override
        public void close() {
            connected = false;
            closed = true;
        }
    }

    static final class FakeSshConnectionFactory implements SshConnectionFactory {
        final AtomicInteger openCount = new AtomicInteger();
        final AtomicInteger diagnoseCount = new AtomicInteger();
        final List<FakeSshConnection> opened = new CopyOnWriteArrayList<>();
        final List<SshTunnel> openedWith = new CopyOnWriteArrayList<>();
        volatile boolean failOpen;
        volatile String failMessage = "connection refused";
        volatile boolean failFetch;
        volatile Boolean lastDiagnoseAlreadyLive;
        volatile HostKeyInfo hostKey = new HostKeyInfo("ssh-ed25519", "SHA256:abc", "AAAAkey");

        @Override
        public SshConnection open(SshTunnel tunnel) throws SshTunnelException {
            openCount.incrementAndGet();
            openedWith.add(tunnel.copy());
            if (failOpen) {
                throw new SshTunnelException(failMessage);
            }
            var connection = new FakeSshConnection();
            opened.add(connection);
            return connection;
        }

        @Override
        public DiagnosticResult diagnose(SshTunnel tunnel, boolean alreadyLive) {
            diagnoseCount.incrementAndGet();
            lastDiagnoseAlreadyLive = alreadyLive;
            openedWith.add(tunnel.copy());
            var result = new DiagnosticResult();
            result.add("DNS resolution", StepStatus.PASS, "resolved", 1);
            result.add("TCP connection", StepStatus.PASS, "reached", 1);
            result.add("Host key", tunnel.isVerifyHostKey() ? StepStatus.PASS : StepStatus.WARN, "host key", 1);
            if (failOpen) {
                result.add("Authentication", StepStatus.FAIL, failMessage, 1);
            } else {
                result.add("Authentication", StepStatus.PASS, "authenticated", 1);
                for (var forward : tunnel.getForwards()) {
                    var skipRemote = alreadyLive && forward.getDirection() == ForwardDirection.REMOTE;
                    result.add("Forward " + forward.describe(),
                            skipRemote ? StepStatus.SKIP : StepStatus.PASS, "probed", 1);
                }
            }
            result.finish();
            return result;
        }

        @Override
        public HostKeyInfo fetchHostKey(String host, int port) throws SshTunnelException {
            if (failFetch) {
                throw new SshTunnelException("cannot reach " + host);
            }
            return hostKey;
        }

        volatile boolean failDerive;
        volatile String derivedPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 oie-tunnel";

        @Override
        public String derivePublicKey(SshTunnel tunnel) throws SshTunnelException {
            if (failDerive) {
                throw new SshTunnelException("Could not decrypt the private key. Check the passphrase.");
            }
            return derivedPublicKey;
        }
    }

    static final class FakeConfigStore implements ConfigStore {
        final Map<String, String> props = new HashMap<>();
        boolean failDecrypt;

        @Override
        public String getProperty(String name) {
            return props.get(name);
        }

        @Override
        public void saveProperty(String name, String value) {
            props.put(name, value);
        }

        @Override
        public String encrypt(String value) {
            return "ENC[" + value + "]";
        }

        @Override
        public String decrypt(String value) {
            if (failDecrypt) {
                throw new RuntimeException("decrypt failure (simulated)");
            }
            if (!value.startsWith("ENC[") || !value.endsWith("]")) {
                throw new RuntimeException("not an encrypted value: " + value);
            }
            return value.substring(4, value.length() - 1);
        }
    }

    static SshTunnel passwordTunnel(String id, String name) {
        var tunnel = new SshTunnel();
        tunnel.setId(id);
        tunnel.setName(name);
        tunnel.setHost("vendor.example.com");
        tunnel.setPort(22);
        tunnel.setUsername("mirth");
        tunnel.setAuthMethod(AuthMethod.PASSWORD);
        tunnel.setPassword("s3cret");
        tunnel.setVerifyHostKey(false);
        tunnel.setForwards(new ArrayList<>(List.of(
                new PortForward(ForwardDirection.LOCAL, "127.0.0.1", 6661, "hl7.internal", 6661))));
        return tunnel;
    }
}
