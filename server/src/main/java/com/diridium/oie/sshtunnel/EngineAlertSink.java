/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.LinkedHashMap;

import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.model.ServerEvent.Level;
import com.mirth.connect.model.ServerEvent.Outcome;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.EventController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reports tunnel up/down edges to the engine as ServerEvents: a WARNING/FAILURE
 * when a tunnel goes down, an INFORMATION/SUCCESS when it recovers. They land in
 * the engine's Events log at a severity an operator already watches, so an
 * outage is visible without opening this plugin's tab.
 *
 * Controllers are resolved lazily and cached: constructing this during the
 * plugin's start() must not depend on controller readiness, and a state edge is
 * infrequent enough that the first-use lookup is free.
 */
public class EngineAlertSink implements TunnelAlertSink {

    private static final Logger log = LoggerFactory.getLogger(EngineAlertSink.class);

    private volatile EventController eventController;
    private volatile String serverId;

    @Override
    public void tunnelDown(SshTunnel tunnel, String reason) {
        dispatch(Level.WARNING, Outcome.FAILURE, "Tunnel Down", tunnel, reason);
    }

    @Override
    public void tunnelRecovered(SshTunnel tunnel) {
        dispatch(Level.INFORMATION, Outcome.SUCCESS, "Tunnel Recovered", tunnel, null);
    }

    private void dispatch(Level level, Outcome outcome, String action, SshTunnel tunnel, String reason) {
        try {
            var attributes = new LinkedHashMap<String, String>();
            attributes.put("Tunnel", tunnel.getName());
            attributes.put("Endpoint", tunnel.getEndpointDescription());
            attributes.put("Action", action);
            if (reason != null && !reason.isEmpty()) {
                attributes.put("Reason", reason);
            }
            controller().dispatchEvent(new ServerEvent(serverId(),
                    SshTunnelServletInterface.PLUGIN_NAME, level, outcome, attributes));
        } catch (Exception e) {
            // Alerting must never break the reconcile loop that calls us.
            log.warn("Failed to dispatch tunnel alert event", e);
        }
    }

    private EventController controller() {
        var current = eventController;
        if (current == null) {
            current = ControllerFactory.getFactory().createEventController();
            eventController = current;
        }
        return current;
    }

    private String serverId() {
        var current = serverId;
        if (current == null) {
            current = ConfigurationController.getInstance().getServerId();
            serverId = current;
        }
        return current;
    }
}
