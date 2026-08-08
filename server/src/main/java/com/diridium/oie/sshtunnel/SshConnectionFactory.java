/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/** Opens SSH connections for tunnels. Production implementation is {@link JschConnectionFactory}. */
public interface SshConnectionFactory {

    /**
     * Connects, authenticates, and establishes every forward of the tunnel.
     * Either returns a fully-established connection or throws; never returns a
     * half-open one.
     */
    SshConnection open(SshTunnel tunnel) throws SshTunnelException;

    /**
     * Runs a staged, non-destructive connection diagnostic: DNS, TCP reach,
     * host-key check, authentication, and per-forward reachability. Never binds
     * a local port (it probes destinations through direct channels), so it is
     * safe to run against a tunnel that is already connected.
     *
     * @param alreadyLive whether the tunnel currently holds a live connection;
     *                    affects how remote (-R) forwards are checked, since
     *                    their server-side listen port is already claimed.
     */
    DiagnosticResult diagnose(SshTunnel tunnel, boolean alreadyLive);

    /** Fetches the server's host key without authenticating, for display and acceptance. */
    HostKeyInfo fetchHostKey(String host, int port) throws SshTunnelException;

    /**
     * Loads the tunnel's private key (decrypting with the passphrase) and returns
     * its public key in OpenSSH authorized_keys format. Throws if the key cannot
     * be read or the passphrase is wrong, which makes this the passphrase check too.
     */
    String derivePublicKey(SshTunnel tunnel) throws SshTunnelException;
}
