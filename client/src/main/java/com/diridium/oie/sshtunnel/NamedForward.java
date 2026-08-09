/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * A local forward paired with the name of the tunnel that owns it, so the edit
 * dialog can name the offending tunnel when a bind address collides. Client-only
 * UI plumbing; never crosses the wire.
 */
public record NamedForward(String tunnelName, PortForward forward) {
}
