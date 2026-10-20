/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.awt.Component;

import com.mirth.connect.client.core.ForbiddenException;
import com.mirth.connect.client.core.TaskConstants;
import com.mirth.connect.client.ui.AuthorizationControllerFactory;
import com.mirth.connect.client.ui.PlatformUI;

/**
 * What the user's role allows, so the tab can hide the changes the server would refuse, and say so plainly
 * when it refuses one anyway (a role changed while the Administrator was open).
 */
final class RoleAccess {

    static final String REFUSED = "You don't have permission to change SSH tunnels. Your role needs "
            + SshTunnelPermissions.MANAGE + ".";

    private RoleAccess() {
    }

    /**
     * Whether the user may change tunnels: the tab's save task, which the server registers with MANAGE.
     * Without an authorization plugin every task is allowed. The server checks the permission either way.
     */
    static boolean canManage() {
        try {
            return AuthorizationControllerFactory.getAuthorizationController()
                    .checkTask(SshTunnelPermissions.SETTINGS_TASK_GROUP, TaskConstants.SETTINGS_SAVE);
        } catch (RuntimeException e) {
            // Hiding is only a convenience: show the buttons and let the server decide.
            return true;
        }
    }

    /** Whether a failed request was refused for want of a permission. */
    static boolean isRefusal(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof ForbiddenException) {
                return true;
            }
        }
        return false;
    }

    /** A refused change as a plain sentence, anything else as the engine's error dialog. */
    static void alertFailure(Component parent, Throwable e) {
        if (isRefusal(e)) {
            PlatformUI.MIRTH_FRAME.alertWarning(parent, REFUSED);
        } else {
            PlatformUI.MIRTH_FRAME.alertThrowable(parent, e);
        }
    }
}
