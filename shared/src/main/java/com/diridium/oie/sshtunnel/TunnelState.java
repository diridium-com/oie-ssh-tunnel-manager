/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/** Runtime state of a tunnel as reported by the server-side manager. */
public enum TunnelState {
    CONNECTED("Connected"),
    CONNECTING("Connecting"),
    RECONNECTING("Reconnecting"),
    DISCONNECTED("Disconnected"),
    FAILED("Failed"),
    DISABLED("Disabled");

    private final String displayName;

    TunnelState(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
