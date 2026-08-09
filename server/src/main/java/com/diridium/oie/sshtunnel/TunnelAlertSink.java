/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * Sink for tunnel up/down state-change alerts.
 *
 * The manager reports only edges: a tunnel that should be up going down, and one
 * coming back after having been down. It deliberately does NOT report routine
 * startup connects or every retry attempt, so wiring this to the engine's event
 * system surfaces real outages without flooding it. Kept as an interface so the
 * manager stays unit-testable without any engine controllers.
 */
public interface TunnelAlertSink {

    /** A tunnel that should be connected has entered a failed/down state. */
    void tunnelDown(SshTunnel tunnel, String reason);

    /** A tunnel that had been down has re-established its connection. */
    void tunnelRecovered(SshTunnel tunnel);

    /** Does nothing; the safe default and the stand-in used by tests. */
    TunnelAlertSink NOOP = new TunnelAlertSink() {
        @Override
        public void tunnelDown(SshTunnel tunnel, String reason) {
        }

        @Override
        public void tunnelRecovered(SshTunnel tunnel) {
        }
    };
}
