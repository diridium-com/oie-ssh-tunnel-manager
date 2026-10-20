/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import com.mirth.connect.client.core.TaskConstants;

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

    /**
     * The settings tab's task group. As for every settings tab, the tab's refresh task needs VIEW and its
     * save task needs MANAGE (registered in getExtensionPermissions()), so Role-Based Access Control hides
     * the tab from users without VIEW, and both Administrators hide its change buttons from users without
     * MANAGE. The web administrator uses the same names, in webadmin/web/tunnel-panel.jsx.
     */
    public static final String SETTINGS_TASK_GROUP = TaskConstants.SETTINGS_KEY_PREFIX + SshTunnelServletInterface.PLUGIN_NAME;

    private SshTunnelPermissions() {
    }
}
