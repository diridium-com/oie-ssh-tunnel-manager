/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * A live SSH session with this tunnel's forwards established. Wrapping JSch
 * behind this interface keeps TunnelManager testable with fakes and keeps the
 * SSH library swappable.
 */
public interface SshConnection {

    boolean isConnected();

    /** Disconnects the session, tearing down all forwards. Never throws. */
    void close();
}
