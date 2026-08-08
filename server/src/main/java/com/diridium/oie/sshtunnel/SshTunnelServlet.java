/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.NoSuchElementException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.SecurityContext;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.model.ServerEvent.Level;
import com.mirth.connect.model.ServerEvent.Outcome;
import com.mirth.connect.server.api.MirthServlet;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.EventController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * REST servlet implementing the tunnel manager API.
 * Extends MirthServlet for automatic permission enforcement via @MirthOperation.
 */
public class SshTunnelServlet extends MirthServlet implements SshTunnelServletInterface {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelServlet.class);

    private final EventController eventController;
    private final String serverId;

    public SshTunnelServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        super(request, sc, PLUGIN_NAME);
        this.eventController = ControllerFactory.getFactory().createEventController();
        this.serverId = ConfigurationController.getInstance().getServerId();
    }

    @Override
    public List<SshTunnel> getTunnels() throws ClientException {
        try {
            return SshTunnelService.getInstance().getTunnelsMasked();
        } catch (Exception e) {
            log.error("Failed to list tunnels", e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public SshTunnel createTunnel(SshTunnel tunnel) throws ClientException {
        try {
            var created = SshTunnelService.getInstance().create(tunnel);
            dispatchEvent("Created", created.getName());
            return created;
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        } catch (IllegalStateException e) {
            throw conflict(e.getMessage());
        } catch (Exception e) {
            log.error("Failed to create tunnel", e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public SshTunnel updateTunnel(String id, SshTunnel tunnel) throws ClientException {
        try {
            var updated = SshTunnelService.getInstance().update(id, tunnel);
            dispatchEvent("Updated", updated.getName());
            return updated;
        } catch (NoSuchElementException e) {
            throw new MirthApiException(Status.NOT_FOUND);
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        } catch (IllegalStateException e) {
            throw conflict(e.getMessage());
        } catch (Exception e) {
            log.error("Failed to update tunnel {}", id, e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public void deleteTunnel(String id) throws ClientException {
        try {
            var name = SshTunnelService.getInstance().getTunnelName(id);
            SshTunnelService.getInstance().delete(id);
            dispatchEvent("Deleted", name);
        } catch (NoSuchElementException e) {
            throw new MirthApiException(Status.NOT_FOUND);
        } catch (IllegalStateException e) {
            throw conflict(e.getMessage());
        } catch (Exception e) {
            log.error("Failed to delete tunnel {}", id, e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public List<SshTunnelStatus> getStatuses() throws ClientException {
        try {
            return SshTunnelService.getInstance().getStatuses();
        } catch (Exception e) {
            log.error("Failed to get tunnel statuses", e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public void startTunnel(String id) throws ClientException {
        try {
            var name = SshTunnelService.getInstance().getTunnelName(id);
            SshTunnelService.getInstance().startTunnel(id);
            dispatchEvent("Started", name);
        } catch (NoSuchElementException e) {
            throw new MirthApiException(Status.NOT_FOUND);
        } catch (Exception e) {
            log.error("Failed to start tunnel {}", id, e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public void stopTunnel(String id) throws ClientException {
        try {
            var name = SshTunnelService.getInstance().getTunnelName(id);
            SshTunnelService.getInstance().stopTunnel(id);
            dispatchEvent("Stopped", name);
        } catch (NoSuchElementException e) {
            throw new MirthApiException(Status.NOT_FOUND);
        } catch (Exception e) {
            log.error("Failed to stop tunnel {}", id, e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public DiagnosticResult testConnection(SshTunnel tunnel) throws ClientException {
        try {
            var result = SshTunnelService.getInstance().testConnection(tunnel);
            dispatchEvent("Connection Test", tunnel.getName() != null && !tunnel.getName().isBlank()
                    ? tunnel.getName() : "(unsaved)");
            return result;
        } catch (Exception e) {
            log.error("Failed to test tunnel connection", e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public List<TunnelEvent> getTunnelEvents(String id) throws ClientException {
        try {
            return SshTunnelService.getInstance().getEvents(id);
        } catch (NoSuchElementException e) {
            throw new MirthApiException(Status.NOT_FOUND);
        } catch (Exception e) {
            log.error("Failed to get events for tunnel {}", id, e);
            throw new MirthApiException(e);
        }
    }

    @Override
    public HostKeyInfo fetchHostKey(String host, int port) throws ClientException {
        try {
            var info = SshTunnelService.getInstance().fetchHostKey(host, port);
            dispatchEvent("Host Key Fetched", host + ":" + port);
            return info;
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        } catch (SshTunnelException e) {
            throw new MirthApiException(e.getMessage());
        } catch (Exception e) {
            log.error("Failed to fetch host key from {}:{}", host, port, e);
            throw new MirthApiException(e);
        }
    }

    private static MirthApiException badRequest(String message) {
        return new MirthApiException(Response.status(Status.BAD_REQUEST).entity(message).build());
    }

    private static MirthApiException conflict(String message) {
        return new MirthApiException(Response.status(Status.CONFLICT).entity(message).build());
    }

    private void dispatchEvent(String action, String tunnelName) {
        var attributes = new LinkedHashMap<String, String>();
        attributes.put("Tunnel", tunnelName);
        attributes.put("Action", action);
        eventController.dispatchEvent(new ServerEvent(
                serverId, PLUGIN_NAME, Level.INFORMATION, Outcome.SUCCESS, attributes));
    }
}
