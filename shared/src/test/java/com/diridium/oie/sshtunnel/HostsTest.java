/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HostsTest {

    @Test
    void acceptsValidIpv4() {
        assertNull(Hosts.validationError("Host", "192.168.1.5"));
        assertNull(Hosts.validationError("Host", "0.0.0.0"));
        assertNull(Hosts.validationError("Host", "255.255.255.255"));
        assertNull(Hosts.validationError("Host", "10.0.0.1"));
    }

    @Test
    void rejectsOutOfRangeOctets() {
        // The reported case: four numeric parts is clearly an IPv4 attempt, so it
        // must be validated strictly rather than shipped off to DNS as a hostname.
        var error = Hosts.validationError("SSH host", "2000.1000.1.1");
        assertNotNull(error);
        assertTrue(error.contains("2000.1000.1.1"), error);
        assertNotNull(Hosts.validationError("Host", "256.1.1.1"));
        assertNotNull(Hosts.validationError("Host", "1.2.3.999"));
    }

    @Test
    void acceptsValidHostnames() {
        assertNull(Hosts.validationError("Host", "example.com"));
        assertNull(Hosts.validationError("Host", "sub.domain.example.com"));
        assertNull(Hosts.validationError("Host", "myserver"));
        assertNull(Hosts.validationError("Host", "host-name.local"));
        assertNull(Hosts.validationError("Host", "db_primary"));
        assertNull(Hosts.validationError("Host", "example.com.")); // trailing dot = FQDN
    }

    @Test
    void rejectsMalformedHostnames() {
        assertNotNull(Hosts.validationError("Host", "bad host"));   // space
        assertNotNull(Hosts.validationError("Host", "-leading.com"));
        assertNotNull(Hosts.validationError("Host", "trailing-.com"));
        assertNotNull(Hosts.validationError("Host", "under@score"));
        assertNotNull(Hosts.validationError("Host", "a".repeat(64) + ".com")); // label > 63
    }

    @Test
    void acceptsPlausibleIpv6() {
        assertNull(Hosts.validationError("Host", "::1"));
        assertNull(Hosts.validationError("Host", "fe80::1"));
        assertNull(Hosts.validationError("Host", "2001:db8::1"));
        assertNull(Hosts.validationError("Host", "::"));
        assertNull(Hosts.validationError("Host", "fe80::1%eth0")); // scope/zone id
    }

    @Test
    void rejectsBadIpv6() {
        assertNotNull(Hosts.validationError("Host", "1:2"));           // too few colons
        assertNotNull(Hosts.validationError("Host", "gg::1"));         // non-hex
        assertNotNull(Hosts.validationError("Host", "1:2:3:4:5:6:7:8:9")); // too many colons
    }

    @Test
    void requiresNonBlank() {
        assertTrue(Hosts.validationError("SSH host", "").contains("required"));
        assertTrue(Hosts.validationError("SSH host", "   ").contains("required"));
        assertTrue(Hosts.validationError("SSH host", null).contains("required"));
    }

    @Test
    void wildcardOnlyWhenAllowed() {
        assertNull(Hosts.validationError("Bind host", "*", true));
        assertNotNull(Hosts.validationError("SSH host", "*", false));
        assertNotNull(Hosts.validationError("SSH host", "*")); // default disallows
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertNull(Hosts.validationError("Host", "  192.168.1.5  "));
        assertNull(Hosts.validationError("Host", " example.com "));
    }
}
