/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSch-backed connection factory using the engine's bundled jsch (server-lib).
 *
 * Everything is configured per JSch instance and per session. JSch's static
 * config (JSch.setConfig / setLogger) is shared JVM-wide with the engine's SFTP
 * connector and must never be touched from here.
 */
public class JschConnectionFactory implements SshConnectionFactory {

    private static final Logger log = LoggerFactory.getLogger(JschConnectionFactory.class);

    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int FETCH_HOST_KEY_TIMEOUT_MS = 10000;
    private static final int TCP_TIMEOUT_MS = 8000;
    private static final int CHANNEL_TIMEOUT_MS = 8000;

    @Override
    public SshConnection open(SshTunnel tunnel) throws SshTunnelException {
        return connect(tunnel, true);
    }

    private SshConnection connect(SshTunnel tunnel, boolean establishForwards) throws SshTunnelException {
        Session session = null;
        try {
            session = openAuthedSession(tunnel);
            if (establishForwards) {
                establishForwards(session, tunnel);
                log.info("Tunnel '{}' connected to {} with {} forward(s)",
                        tunnel.getName(), tunnel.getEndpointDescription(), tunnel.getForwards().size());
            }
            return new JschSshConnection(session);
        } catch (Exception e) {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
            if (e instanceof SshTunnelException ste) {
                throw ste;
            }
            throw new SshTunnelException(describeFailure(e, tunnel), e);
        }
    }

    /** Connects and authenticates a session with no forwards; caller owns disconnect. */
    private Session openAuthedSession(SshTunnel tunnel) throws JSchException, SshTunnelException {
        var jsch = new JSch();
        configureIdentity(jsch, tunnel);
        var session = jsch.getSession(tunnel.getUsername(), tunnel.getHost(), tunnel.getPort());
        configureAuth(session, tunnel);
        configureHostKeyChecking(session, tunnel);
        configureKeepAlive(session, tunnel);
        session.connect(CONNECT_TIMEOUT_MS);
        return session;
    }

    @Override
    public DiagnosticResult diagnose(SshTunnel tunnel, boolean alreadyLive) {
        var result = new DiagnosticResult();

        // 1. DNS resolution
        long t = System.nanoTime();
        try {
            var addrs = InetAddress.getAllByName(tunnel.getHost());
            var ips = new StringBuilder();
            for (var addr : addrs) {
                if (ips.length() > 0) {
                    ips.append(", ");
                }
                ips.append(addr.getHostAddress());
            }
            result.add("DNS resolution", StepStatus.PASS, tunnel.getHost() + " -> " + ips, ms(t));
        } catch (Exception e) {
            result.add("DNS resolution", StepStatus.FAIL, "cannot resolve " + tunnel.getHost() + ": " + rootMessage(e), ms(t));
            result.add("TCP connection", StepStatus.SKIP, "host did not resolve", 0);
            result.finish();
            return result;
        }

        // 2. TCP reachability of the SSH port
        t = System.nanoTime();
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(tunnel.getHost(), tunnel.getPort()), TCP_TIMEOUT_MS);
            result.add("TCP connection", StepStatus.PASS,
                    "reached " + tunnel.getHost() + ":" + tunnel.getPort(), ms(t));
        } catch (Exception e) {
            result.add("TCP connection", StepStatus.FAIL,
                    "cannot reach " + tunnel.getHost() + ":" + tunnel.getPort() + ": " + rootMessage(e), ms(t));
            result.finish();
            return result;
        }

        // 3. Host key
        t = System.nanoTime();
        try {
            var hostKey = fetchHostKey(tunnel.getHost(), tunnel.getPort());
            var offered = hostKey.getKeyType() + " " + hostKey.getFingerprint();
            if (!tunnel.isVerifyHostKey()) {
                result.add("Host key", StepStatus.WARN, "verification disabled; server offers " + offered, ms(t));
            } else if (tunnel.getAcceptedHostKey() == null || tunnel.getAcceptedHostKey().isEmpty()) {
                result.add("Host key", StepStatus.FAIL,
                        "verification enabled but no key accepted; server offers " + offered, ms(t));
            } else if (tunnel.getAcceptedHostKey().equals(hostKey.getPublicKey())) {
                result.add("Host key", StepStatus.PASS, "matches accepted " + offered, ms(t));
            } else {
                result.add("Host key", StepStatus.FAIL,
                        "MISMATCH: server offers " + offered + " but a different key was accepted", ms(t));
            }
        } catch (SshTunnelException e) {
            result.add("Host key", StepStatus.WARN, "could not fetch host key: " + rootMessage(e), ms(t));
        }

        // 4. Authentication (opens the session reused for forward probes)
        t = System.nanoTime();
        Session session = null;
        try {
            session = openAuthedSession(tunnel);
            result.add("Authentication", StepStatus.PASS, "authenticated as " + tunnel.getUsername(), ms(t));
        } catch (Exception e) {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
            result.add("Authentication", StepStatus.FAIL, describeFailure(e, tunnel), ms(t));
            for (var forward : tunnel.getForwards()) {
                result.add("Forward " + forward.describe(), StepStatus.SKIP, "not authenticated", 0);
            }
            result.finish();
            return result;
        }

        // 5. Per-forward reachability
        try {
            for (var forward : tunnel.getForwards()) {
                probeForward(result, session, forward, alreadyLive);
            }
        } finally {
            session.disconnect();
        }

        result.finish();
        return result;
    }

    private void probeForward(DiagnosticResult result, Session session, PortForward forward, boolean alreadyLive) {
        var label = "Forward " + forward.describe();
        long t = System.nanoTime();

        if (forward.getDirection() == ForwardDirection.LOCAL) {
            // Open a direct channel to the destination through the SSH server —
            // the same path a local forward carries — without binding any local
            // port, so this never conflicts with a live tunnel.
            Channel channel = null;
            try {
                channel = session.openChannel("direct-tcpip");
                var direct = (ChannelDirectTCPIP) channel;
                direct.setHost(forward.getDestinationHost());
                direct.setPort(forward.getDestinationPort());
                direct.setOrgIPAddress("127.0.0.1");
                direct.setOrgPort(0);
                channel.connect(CHANNEL_TIMEOUT_MS);
                if (channel.isConnected()) {
                    result.add(label, StepStatus.PASS, "destination "
                            + forward.getDestinationHost() + ":" + forward.getDestinationPort()
                            + " reachable through the tunnel", ms(t));
                } else {
                    result.add(label, StepStatus.FAIL, "channel to destination did not open", ms(t));
                }
            } catch (Exception e) {
                result.add(label, StepStatus.FAIL, "destination "
                        + forward.getDestinationHost() + ":" + forward.getDestinationPort()
                        + " not reachable: " + rootMessage(e), ms(t));
            } finally {
                if (channel != null) {
                    channel.disconnect();
                }
            }
        } else if (alreadyLive) {
            // The server-side listen port is already held by the live tunnel;
            // re-requesting it would falsely fail.
            result.add(label, StepStatus.SKIP,
                    "tunnel is connected; this remote forward is already active on the server", 0);
        } else {
            // Confirm the server permits the remote forward, then release it.
            // End-to-end (the server connecting back) cannot be driven from here.
            try {
                session.setPortForwardingR(forward.getBindHost(), forward.getBindPort(),
                        forward.getDestinationHost(), forward.getDestinationPort());
                session.delPortForwardingR(forward.getBindHost(), forward.getBindPort());
                result.add(label, StepStatus.PASS, "server granted remote listen on "
                        + forward.getBindHost() + ":" + forward.getBindPort()
                        + " (return path not tested from this side)", ms(t));
            } catch (Exception e) {
                result.add(label, StepStatus.FAIL, "server refused remote forward on "
                        + forward.getBindHost() + ":" + forward.getBindPort() + ": " + rootMessage(e), ms(t));
            }
        }
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    private static String rootMessage(Throwable e) {
        var cause = e.getCause() != null ? e.getCause() : e;
        return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
    }

    @Override
    public HostKeyInfo fetchHostKey(String host, int port) throws SshTunnelException {
        Session session = null;
        JSchException connectFailure = null;
        try {
            var jsch = new JSch();
            session = jsch.getSession("host-key-probe", host, port);
            // The key is captured during KEX, before authentication. Auth is
            // expected to fail; we never send credentials.
            session.setConfig("StrictHostKeyChecking", "no");
            session.setConfig("PreferredAuthentications", "publickey");
            try {
                session.connect(FETCH_HOST_KEY_TIMEOUT_MS);
            } catch (JSchException e) {
                connectFailure = e;
            }

            var hostKey = session.getHostKey();
            if (hostKey == null) {
                var reason = connectFailure != null ? connectFailure.getMessage() : "no key exchanged";
                throw new SshTunnelException("Could not fetch host key from " + host + ":" + port + ": " + reason,
                        connectFailure);
            }
            var keyBytes = Base64.getDecoder().decode(hostKey.getKey());
            return new HostKeyInfo(hostKey.getType(), sha256Fingerprint(keyBytes), hostKey.getKey());
        } catch (SshTunnelException e) {
            throw e;
        } catch (Exception e) {
            throw new SshTunnelException("Could not fetch host key from " + host + ":" + port + ": " + e.getMessage(), e);
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }
    }

    private static void configureIdentity(JSch jsch, SshTunnel tunnel) throws JSchException {
        if (tunnel.getAuthMethod() != AuthMethod.PRIVATE_KEY) {
            return;
        }
        var passphrase = tunnel.getPrivateKeyPassphrase();
        if (tunnel.getKeySource() == KeySource.INLINE) {
            var keyBytes = tunnel.getPrivateKeyPem().getBytes(StandardCharsets.UTF_8);
            var passphraseBytes = passphrase == null || passphrase.isEmpty()
                    ? null : passphrase.getBytes(StandardCharsets.UTF_8);
            jsch.addIdentity("tunnel-" + tunnel.getId(), keyBytes, null, passphraseBytes);
        } else {
            if (passphrase == null || passphrase.isEmpty()) {
                jsch.addIdentity(tunnel.getPrivateKeyPath());
            } else {
                jsch.addIdentity(tunnel.getPrivateKeyPath(), passphrase);
            }
        }
    }

    private static void configureAuth(Session session, SshTunnel tunnel) {
        if (tunnel.getAuthMethod() == AuthMethod.PASSWORD) {
            session.setPassword(tunnel.getPassword());
            session.setConfig("PreferredAuthentications", "password,keyboard-interactive");
            // Some servers only offer keyboard-interactive; answer its prompt
            // with the password, the same way the engine's SFTP connector does.
            session.setUserInfo(new PasswordUserInfo(tunnel.getPassword()));
        } else {
            session.setConfig("PreferredAuthentications", "publickey");
        }
    }

    private static void configureHostKeyChecking(Session session, SshTunnel tunnel) throws SshTunnelException {
        if (!tunnel.isVerifyHostKey()) {
            session.setConfig("StrictHostKeyChecking", "no");
            return;
        }
        if (tunnel.getAcceptedHostKey() == null || tunnel.getAcceptedHostKey().isEmpty()) {
            throw new SshTunnelException("Host key verification is enabled but no host key has been accepted"
                    + " for tunnel '" + tunnel.getName() + "'. Fetch and accept the host key, or disable verification.");
        }
        session.setConfig("StrictHostKeyChecking", "yes");
        session.setHostKeyRepository(new AcceptedHostKeyRepository(
                Base64.getDecoder().decode(tunnel.getAcceptedHostKey())));
    }

    private static void configureKeepAlive(Session session, SshTunnel tunnel) throws JSchException {
        if (tunnel.getServerAliveIntervalSeconds() > 0) {
            // Note: in JSch this also becomes the socket read timeout.
            session.setServerAliveInterval(tunnel.getServerAliveIntervalSeconds() * 1000);
            session.setServerAliveCountMax(Math.max(1, tunnel.getServerAliveCountMax()));
        }
    }

    private static void establishForwards(Session session, SshTunnel tunnel) throws JSchException {
        for (var forward : tunnel.getForwards()) {
            if (forward.getDirection() == ForwardDirection.LOCAL) {
                session.setPortForwardingL(forward.getBindHost(), forward.getBindPort(),
                        forward.getDestinationHost(), forward.getDestinationPort());
            } else {
                session.setPortForwardingR(forward.getBindHost(), forward.getBindPort(),
                        forward.getDestinationHost(), forward.getDestinationPort());
            }
        }
    }

    /** Maps JSch's stringly-typed failures to something an admin can act on. */
    private static String describeFailure(Exception e, SshTunnel tunnel) {
        var endpoint = tunnel.getEndpointDescription();
        var message = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

        if (e instanceof JSchException) {
            if (message.startsWith("Auth fail") || message.startsWith("Auth cancel")) {
                return "Authentication failed for " + endpoint + " (check credentials and auth method)";
            }
            if (message.contains("HostKey") || (message.contains("reject") && message.contains("key"))) {
                return "Host key verification failed for " + endpoint + ": " + message
                        + ". If the server's key legitimately changed, fetch and accept it again.";
            }
            var cause = e.getCause();
            if (cause instanceof UnknownHostException) {
                return "Unknown host: " + tunnel.getHost();
            }
            if (cause instanceof ConnectException || cause instanceof NoRouteToHostException
                    || cause instanceof SocketTimeoutException) {
                return "Cannot reach " + tunnel.getHost() + ":" + tunnel.getPort() + " (" + cause.getMessage() + ")";
            }
        }
        return message;
    }

    private static String sha256Fingerprint(byte[] keyBytes) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256").digest(keyBytes);
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
    }

    /** A session wrapper; close is idempotent and never throws. */
    private static class JschSshConnection implements SshConnection {

        private final Session session;

        JschSshConnection(Session session) {
            this.session = session;
        }

        @Override
        public boolean isConnected() {
            return session.isConnected();
        }

        @Override
        public void close() {
            try {
                session.disconnect();
            } catch (Exception e) {
                log.debug("Error disconnecting session", e);
            }
        }
    }

    /**
     * Accepts exactly one host key: the one the admin fetched and approved.
     * Anything else reports CHANGED, which makes JSch refuse the connection
     * under StrictHostKeyChecking=yes.
     */
    static class AcceptedHostKeyRepository implements HostKeyRepository {

        private final byte[] acceptedKey;

        AcceptedHostKeyRepository(byte[] acceptedKey) {
            this.acceptedKey = acceptedKey;
        }

        @Override
        public int check(String host, byte[] key) {
            return Arrays.equals(acceptedKey, key) ? OK : CHANGED;
        }

        @Override
        public void add(HostKey hostkey, UserInfo ui) {
            // Never learns new keys; acceptance happens explicitly in the UI.
        }

        @Override
        public void remove(String host, String type) {
        }

        @Override
        public void remove(String host, String type, byte[] key) {
        }

        @Override
        public String getKnownHostsRepositoryID() {
            return "ssh-tunnel-manager";
        }

        @Override
        public HostKey[] getHostKey() {
            return new HostKey[0];
        }

        @Override
        public HostKey[] getHostKey(String host, String type) {
            return new HostKey[0];
        }
    }

    /** Answers password and keyboard-interactive prompts; never prompts a human. */
    private static class PasswordUserInfo implements UserInfo, UIKeyboardInteractive {

        private final String password;

        PasswordUserInfo(String password) {
            this.password = password;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public String getPassphrase() {
            return null;
        }

        @Override
        public boolean promptPassword(String message) {
            return true;
        }

        @Override
        public boolean promptPassphrase(String message) {
            return false;
        }

        @Override
        public boolean promptYesNo(String message) {
            return false;
        }

        @Override
        public void showMessage(String message) {
        }

        @Override
        public String[] promptKeyboardInteractive(String destination, String name, String instruction,
                String[] prompt, boolean[] echo) {
            var answers = new String[prompt.length];
            Arrays.fill(answers, password);
            return answers;
        }
    }
}
