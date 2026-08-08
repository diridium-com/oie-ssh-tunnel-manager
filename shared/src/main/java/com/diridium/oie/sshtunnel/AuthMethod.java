/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/** How the tunnel authenticates to the SSH server. */
public enum AuthMethod {
    PASSWORD("Password"),
    PRIVATE_KEY("Private Key");

    private final String displayName;

    AuthMethod(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
