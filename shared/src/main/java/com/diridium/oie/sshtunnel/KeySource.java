/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/** Where the private key for PRIVATE_KEY auth comes from. */
public enum KeySource {
    FILE("File on server"),
    INLINE("Pasted key");

    private final String displayName;

    KeySource(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
