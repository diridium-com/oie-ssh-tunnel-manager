/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * Host/IP field validation. Rather than accept anything and let DNS reject it at
 * connect time, this catches obvious garbage up front: an IPv4-shaped string with
 * out-of-range octets (e.g. 2000.1000.1.1), or a hostname with illegal characters.
 */
public final class Hosts {

    private Hosts() {
    }

    /**
     * @return null if {@code host} is a valid IPv4, IPv6, or hostname; otherwise a
     *         human-readable error message prefixed with {@code label}.
     */
    public static String validationError(String label, String host) {
        return validationError(label, host, false);
    }

    /**
     * @param allowWildcard when true, a bare {@code *} is accepted — valid for a
     *                      forward bind host meaning "all local interfaces", but
     *                      never for an SSH host or a forward destination.
     * @return null if {@code host} is valid; otherwise a human-readable error
     *         message prefixed with {@code label}.
     */
    public static String validationError(String label, String host, boolean allowWildcard) {
        if (host == null || host.trim().isEmpty()) {
            return label + " is required";
        }
        var h = host.trim();

        if (allowWildcard && h.equals("*")) {
            return null;
        }

        if (h.indexOf(':') >= 0) {
            return isPlausibleIpv6(h) ? null : label + " '" + host + "' is not a valid IPv6 address";
        }

        var parts = h.split("\\.", -1);
        // Four all-numeric parts is an IPv4 attempt — validate it strictly rather
        // than fall through to hostname rules and ship a bad octet off to DNS.
        if (parts.length == 4 && allNumeric(parts)) {
            for (var part : parts) {
                if (!isOctet(part)) {
                    return label + " '" + host + "' is not a valid IP address (each octet must be 0-255)";
                }
            }
            return null;
        }

        return isValidHostname(h) ? null : label + " '" + host + "' is not a valid hostname or IP address";
    }

    private static boolean allNumeric(String[] parts) {
        for (var part : parts) {
            if (part.isEmpty()) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                if (part.charAt(i) < '0' || part.charAt(i) > '9') {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean isOctet(String part) {
        if (part.isEmpty() || part.length() > 3) {
            return false;
        }
        try {
            int value = Integer.parseInt(part);
            return value >= 0 && value <= 255;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isValidHostname(String host) {
        var h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host; // trailing dot = FQDN
        if (h.isEmpty() || h.length() > 253) {
            return false;
        }
        for (var label : h.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                var c = label.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '-' || c == '_';
                if (!ok) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean isPlausibleIpv6(String host) {
        var addr = host;
        int zone = addr.indexOf('%'); // scope/zone id, e.g. fe80::1%eth0
        if (zone >= 0) {
            addr = addr.substring(0, zone);
        }
        long colons = 0;
        for (int i = 0; i < addr.length(); i++) {
            var c = addr.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!(hex || c == ':' || c == '.')) {
                return false;
            }
            if (c == ':') {
                colons++;
            }
        }
        return colons >= 2 && colons <= 7;
    }
}
