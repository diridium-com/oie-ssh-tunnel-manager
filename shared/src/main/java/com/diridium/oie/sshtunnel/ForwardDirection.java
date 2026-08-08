/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * Direction of a port forward, matching OpenSSH semantics:
 * LOCAL is ssh -L (listen on the engine host, forward through the tunnel to a
 * destination reachable from the SSH server), REMOTE is ssh -R (listen on the
 * SSH server, forward back to a destination reachable from the engine host).
 */
public enum ForwardDirection {
    LOCAL("Local (-L)"),
    REMOTE("Remote (-R)");

    private final String displayName;

    ForwardDirection(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
