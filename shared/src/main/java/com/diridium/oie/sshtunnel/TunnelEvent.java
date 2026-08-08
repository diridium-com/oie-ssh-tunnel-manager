/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;

/** One entry in a tunnel's connection history: a timestamped state change or error. */
public class TunnelEvent implements Serializable {

    /** Severity, for filtering and display coloring. */
    public enum Level {
        INFO, WARN, ERROR
    }

    private long timestamp;
    private Level level = Level.INFO;
    private String message = "";

    public TunnelEvent() {
    }

    public TunnelEvent(long timestamp, Level level, String message) {
        this.timestamp = timestamp;
        this.level = level;
        this.message = message;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public Level getLevel() {
        return level;
    }

    public void setLevel(Level level) {
        this.level = level;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return timestamp + " [" + level + "] " + message;
    }
}
