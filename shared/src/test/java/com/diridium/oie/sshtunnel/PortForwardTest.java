/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PortForwardTest {

    private static PortForward local(String host, int port) {
        return new PortForward(ForwardDirection.LOCAL, host, port, "dest", 1);
    }

    @Test
    void sameHostSamePortCollides() {
        assertTrue(local("127.0.0.1", 6661).localBindCollidesWith(local("127.0.0.1", 6661)));
    }

    @Test
    void differentPortDoesNotCollide() {
        assertFalse(local("127.0.0.1", 6661).localBindCollidesWith(local("127.0.0.1", 6662)));
    }

    @Test
    void differentSpecificHostsDoNotCollide() {
        assertFalse(local("127.0.0.1", 6661).localBindCollidesWith(local("192.168.1.5", 6661)));
    }

    @Test
    void wildcardCollidesWithAnyHostOnSamePort() {
        assertTrue(local("0.0.0.0", 6661).localBindCollidesWith(local("127.0.0.1", 6661)));
        assertTrue(local("127.0.0.1", 6661).localBindCollidesWith(local("0.0.0.0", 6661)));
        assertTrue(local("", 6661).localBindCollidesWith(local("10.0.0.1", 6661)));
    }

    @Test
    void localhostAndLoopbackAreTheSame() {
        assertTrue(local("localhost", 6661).localBindCollidesWith(local("127.0.0.1", 6661)));
    }

    @Test
    void remoteForwardsNeverCollideViaThisCheck() {
        var remote = new PortForward(ForwardDirection.REMOTE, "0.0.0.0", 6661, "dest", 1);
        assertFalse(remote.localBindCollidesWith(local("0.0.0.0", 6661)));
        assertFalse(local("0.0.0.0", 6661).localBindCollidesWith(remote));
    }
}
