/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/** Outcome of one step in a connection diagnostic. */
public enum StepStatus {
    PASS("Pass"),
    WARN("Warning"),
    FAIL("Fail"),
    SKIP("Skipped");

    private final String displayName;

    StepStatus(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
