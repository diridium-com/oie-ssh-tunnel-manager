/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Method;
import java.util.Set;

import com.mirth.connect.client.core.api.MirthOperation;

import org.junit.jupiter.api.Test;

/**
 * Verifies every @MirthOperation on the servlet interface maps to one of this
 * plugin's own permissions with the expected auditable flag, and that read and
 * write operations are separated correctly. Catches permission drift before it
 * ships: an operation added with a wrong or core permission would return 403 at
 * runtime with no compile-time symptom.
 */
class SshTunnelServletInterfacePermissionsTest {

    private static final Set<String> READ_OPS = Set.of("getTunnels", "getStatuses", "getTunnelEvents");

    @Test
    void everyOperationUsesAPluginPermissionWithCorrectAuditable() {
        int operationCount = 0;
        for (Method method : SshTunnelServletInterface.class.getDeclaredMethods()) {
            var op = method.getAnnotation(MirthOperation.class);
            if (op == null) {
                continue;
            }
            operationCount++;

            var permission = op.permission();
            assertTrue(permission.equals(SshTunnelPermissions.VIEW) || permission.equals(SshTunnelPermissions.MANAGE),
                    op.name() + " must use a plugin permission, not '" + permission + "'");

            if (READ_OPS.contains(op.name())) {
                assertEquals(SshTunnelPermissions.VIEW, permission, op.name() + " should require VIEW");
                assertFalse(op.auditable(), op.name() + " (a read) should not be auditable");
            } else {
                assertEquals(SshTunnelPermissions.MANAGE, permission, op.name() + " should require MANAGE");
            }
        }
        assertEquals(11, operationCount, "unexpected number of annotated operations");
    }

    @Test
    void mutatingOperationsAreAuditable() {
        assertAuditable("createTunnel", true);
        assertAuditable("updateTunnel", true);
        assertAuditable("deleteTunnel", true);
        assertAuditable("startTunnel", true);
        assertAuditable("stopTunnel", true);
        assertAuditable("testConnection", true);
        assertAuditable("fetchHostKey", true);
        assertAuditable("derivePublicKey", true);
    }

    private void assertAuditable(String opName, boolean expected) {
        for (Method method : SshTunnelServletInterface.class.getDeclaredMethods()) {
            var op = method.getAnnotation(MirthOperation.class);
            if (op != null && op.name().equals(opName)) {
                assertEquals(expected, op.auditable(), opName + " auditable should be " + expected);
                return;
            }
        }
        fail("No @MirthOperation named '" + opName + "'");
    }
}
