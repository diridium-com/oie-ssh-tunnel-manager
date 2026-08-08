/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import com.mirth.connect.client.core.TaskConstants;
import com.mirth.connect.model.ExtensionPermission;

import org.junit.jupiter.api.Test;

/**
 * Verifies the plugin publishes both permissions to RBAC with operation names
 * derived by reflection (so an operation added later cannot ship unregistered)
 * and the settings-tab composite task on the view permission.
 */
class SshTunnelServicePluginPermissionsTest {

    private ExtensionPermission find(ExtensionPermission[] perms, String displayName) {
        return Arrays.stream(perms)
                .filter(p -> p.getDisplayName().equals(displayName))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no permission '" + displayName + "'"));
    }

    @Test
    void publishesBothPermissionsWithDerivedOperations() {
        var perms = new SshTunnelServicePlugin().getExtensionPermissions();
        assertEquals(2, perms.length);

        var view = find(perms, SshTunnelPermissions.VIEW);
        var manage = find(perms, SshTunnelPermissions.MANAGE);

        assertNotNull(view.getExtensionName());
        assertEquals(SshTunnelServletInterface.PLUGIN_NAME, view.getExtensionName());

        var viewOps = List.of(view.getOperationNames());
        assertTrue(viewOps.contains("getTunnels"), "view ops: " + viewOps);
        assertTrue(viewOps.contains("getStatuses"), "view ops: " + viewOps);
        assertTrue(viewOps.contains("getTunnelEvents"), "view ops: " + viewOps);

        var manageOps = List.of(manage.getOperationNames());
        assertTrue(manageOps.containsAll(List.of(
                "createTunnel", "updateTunnel", "deleteTunnel",
                "startTunnel", "stopTunnel", "testConnection", "fetchHostKey", "derivePublicKey")),
                "manage ops: " + manageOps);

        // Every annotated operation is registered under exactly one permission.
        assertEquals(11, viewOps.size() + manageOps.size());
    }

    @Test
    void viewPermissionCarriesSettingsTabTask() {
        var perms = new SshTunnelServicePlugin().getExtensionPermissions();
        var view = find(perms, SshTunnelPermissions.VIEW);

        var expectedTask = TaskConstants.SETTINGS_KEY_PREFIX + SshTunnelServletInterface.PLUGIN_NAME
                + "/" + TaskConstants.SETTINGS_REFRESH;
        assertTrue(List.of(view.getTaskNames()).contains(expectedTask),
                "view should gate the settings tab via " + expectedTask);
    }
}
