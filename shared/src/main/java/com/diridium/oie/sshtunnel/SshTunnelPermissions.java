/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * Permission names for this plugin's operations.
 *
 * These are the plugin's own permissions, published to RBAC via
 * getExtensionPermissions(). Extension servlet operations reach the
 * authorization controller under the composite name
 * "SSH Tunnel Manager#&lt;operation&gt;", so naming a core engine permission in
 * &#64;MirthOperation would never match; the plugin must declare its own.
 */
public final class SshTunnelPermissions {

    public static final String VIEW = "viewSshTunnels";
    public static final String MANAGE = "manageSshTunnels";

    private SshTunnelPermissions() {
    }
}
