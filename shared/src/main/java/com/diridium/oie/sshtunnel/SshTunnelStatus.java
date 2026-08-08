/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;

/** Point-in-time runtime status of one tunnel, reported by the server-side manager. */
public class SshTunnelStatus implements Serializable {

    private String tunnelId;
    private TunnelState state = TunnelState.DISCONNECTED;
    private String lastError = "";
    /** Epoch millis of the current connection, 0 when not connected. */
    private long connectedSince;
    /** Consecutive failed connection attempts since the last success. */
    private int failedAttempts;
    /** Epoch millis of the next scheduled reconnect attempt, 0 when none. */
    private long nextRetryAt;

    public SshTunnelStatus() {
    }

    public SshTunnelStatus(String tunnelId, TunnelState state) {
        this.tunnelId = tunnelId;
        this.state = state;
    }

    public String getTunnelId() {
        return tunnelId;
    }

    public void setTunnelId(String tunnelId) {
        this.tunnelId = tunnelId;
    }

    public TunnelState getState() {
        return state;
    }

    public void setState(TunnelState state) {
        this.state = state;
    }

    public String getLastError() {
        return lastError;
    }

    public void setLastError(String lastError) {
        this.lastError = lastError;
    }

    public long getConnectedSince() {
        return connectedSince;
    }

    public void setConnectedSince(long connectedSince) {
        this.connectedSince = connectedSince;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public long getNextRetryAt() {
        return nextRetryAt;
    }

    public void setNextRetryAt(long nextRetryAt) {
        this.nextRetryAt = nextRetryAt;
    }

    @Override
    public String toString() {
        return "SshTunnelStatus[" + tunnelId + ", " + state + (lastError.isEmpty() ? "" : ", " + lastError) + "]";
    }
}
