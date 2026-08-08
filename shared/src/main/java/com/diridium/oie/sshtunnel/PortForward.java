/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;
import java.util.Objects;

/**
 * One port forward within a tunnel.
 *
 * LOCAL: bindHost:bindPort listens on the engine host; connections are carried
 * through the tunnel and delivered to destinationHost:destinationPort as seen
 * from the SSH server.
 *
 * REMOTE: bindHost:bindPort listens on the SSH server; connections are carried
 * back through the tunnel and delivered to destinationHost:destinationPort as
 * seen from the engine host.
 */
public class PortForward implements Serializable {

    private ForwardDirection direction = ForwardDirection.LOCAL;
    private String bindHost = "127.0.0.1";
    private int bindPort;
    private String destinationHost = "";
    private int destinationPort;

    public PortForward() {
    }

    public PortForward(ForwardDirection direction, String bindHost, int bindPort,
            String destinationHost, int destinationPort) {
        this.direction = direction;
        this.bindHost = bindHost;
        this.bindPort = bindPort;
        this.destinationHost = destinationHost;
        this.destinationPort = destinationPort;
    }

    public ForwardDirection getDirection() {
        return direction;
    }

    public void setDirection(ForwardDirection direction) {
        this.direction = direction;
    }

    public String getBindHost() {
        return bindHost;
    }

    public void setBindHost(String bindHost) {
        this.bindHost = bindHost;
    }

    public int getBindPort() {
        return bindPort;
    }

    public void setBindPort(int bindPort) {
        this.bindPort = bindPort;
    }

    public String getDestinationHost() {
        return destinationHost;
    }

    public void setDestinationHost(String destinationHost) {
        this.destinationHost = destinationHost;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }

    public PortForward copy() {
        return new PortForward(direction, bindHost, bindPort, destinationHost, destinationPort);
    }

    /**
     * True if this and {@code other} are both LOCAL forwards whose bind address
     * would conflict on the engine host (same port, and overlapping bind host —
     * a wildcard bind like 0.0.0.0 overlaps any host). Two such forwards can
     * never both listen at once.
     */
    public boolean localBindCollidesWith(PortForward other) {
        if (direction != ForwardDirection.LOCAL || other.direction != ForwardDirection.LOCAL) {
            return false;
        }
        if (bindPort != other.bindPort) {
            return false;
        }
        var a = normalizeBindHost(bindHost);
        var b = normalizeBindHost(other.bindHost);
        return a.equals("*") || b.equals("*") || a.equals(b);
    }

    private static String normalizeBindHost(String host) {
        if (host == null) {
            return "*";
        }
        var h = host.trim().toLowerCase();
        if (h.isEmpty() || h.equals("0.0.0.0") || h.equals("::") || h.equals("*")) {
            return "*";
        }
        if (h.equals("localhost")) {
            return "127.0.0.1";
        }
        return h;
    }

    /** Short one-line description for tables and log lines, e.g. "L 127.0.0.1:6661 -> vendor:6661". */
    public String describe() {
        var arrow = direction == ForwardDirection.LOCAL ? "L" : "R";
        return arrow + " " + bindHost + ":" + bindPort + " -> " + destinationHost + ":" + destinationPort;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PortForward other)) {
            return false;
        }
        return bindPort == other.bindPort
                && destinationPort == other.destinationPort
                && direction == other.direction
                && Objects.equals(bindHost, other.bindHost)
                && Objects.equals(destinationHost, other.destinationHost);
    }

    @Override
    public int hashCode() {
        return Objects.hash(direction, bindHost, bindPort, destinationHost, destinationPort);
    }

    @Override
    public String toString() {
        return describe();
    }
}
