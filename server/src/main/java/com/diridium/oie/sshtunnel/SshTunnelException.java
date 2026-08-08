/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/** Failure to connect, authenticate, or establish forwards for a tunnel. */
public class SshTunnelException extends Exception {

    public SshTunnelException(String message) {
        super(message);
    }

    public SshTunnelException(String message, Throwable cause) {
        super(message, cause);
    }
}
