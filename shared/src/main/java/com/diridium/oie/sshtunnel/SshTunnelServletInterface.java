/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.Operation.ExecuteType;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/extensions/oie-ssh-tunnel-manager")
@Tag(name = "SSH Tunnel Manager")
@Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
@Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
public interface SshTunnelServletInterface extends BaseServletInterface {

    String PLUGIN_NAME = "SSH Tunnel Manager";

    // ========== Tunnel CRUD ==========

    @GET
    @Path("/tunnels")
    @Operation(summary = "List all tunnels (secrets masked)")
    @MirthOperation(name = "getTunnels", display = "List SSH tunnels",
            permission = SshTunnelPermissions.VIEW, type = ExecuteType.ASYNC, auditable = false)
    List<SshTunnel> getTunnels() throws ClientException;

    @POST
    @Path("/tunnels")
    @Operation(summary = "Create a tunnel")
    @MirthOperation(name = "createTunnel", display = "Create SSH tunnel",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.SYNC)
    SshTunnel createTunnel(
            @Param("tunnel") @Parameter(description = "The tunnel to create", required = true)
            SshTunnel tunnel) throws ClientException;

    @PUT
    @Path("/tunnels/{id}")
    @Operation(summary = "Update a tunnel (masked secrets keep their stored values)")
    @MirthOperation(name = "updateTunnel", display = "Update SSH tunnel",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.SYNC)
    SshTunnel updateTunnel(
            @Param("id") @Parameter(description = "Tunnel ID", required = true)
            @PathParam("id") String id,
            @Param("tunnel") @Parameter(description = "The updated tunnel", required = true)
            SshTunnel tunnel) throws ClientException;

    @DELETE
    @Path("/tunnels/{id}")
    @Operation(summary = "Delete a tunnel and stop it if running")
    @MirthOperation(name = "deleteTunnel", display = "Delete SSH tunnel",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.SYNC)
    void deleteTunnel(
            @Param("id") @Parameter(description = "Tunnel ID", required = true)
            @PathParam("id") String id) throws ClientException;

    // ========== Runtime control & status ==========

    @GET
    @Path("/statuses")
    @Operation(summary = "Runtime status of every tunnel")
    @MirthOperation(name = "getStatuses", display = "Get SSH tunnel statuses",
            permission = SshTunnelPermissions.VIEW, type = ExecuteType.ASYNC, auditable = false)
    List<SshTunnelStatus> getStatuses() throws ClientException;

    @GET
    @Path("/tunnels/{id}/events")
    @Operation(summary = "Recent connection-history events for a tunnel")
    @MirthOperation(name = "getTunnelEvents", display = "Get SSH tunnel events",
            permission = SshTunnelPermissions.VIEW, type = ExecuteType.ASYNC, auditable = false)
    List<TunnelEvent> getTunnelEvents(
            @Param("id") @Parameter(description = "Tunnel ID", required = true)
            @PathParam("id") String id) throws ClientException;

    @POST
    @Path("/tunnels/{id}/_start")
    @Operation(summary = "Start (connect) a tunnel now")
    @MirthOperation(name = "startTunnel", display = "Start SSH tunnel",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.ASYNC)
    void startTunnel(
            @Param("id") @Parameter(description = "Tunnel ID", required = true)
            @PathParam("id") String id) throws ClientException;

    @POST
    @Path("/tunnels/{id}/_stop")
    @Operation(summary = "Stop (disconnect) a tunnel until restarted or re-enabled")
    @MirthOperation(name = "stopTunnel", display = "Stop SSH tunnel",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.ASYNC)
    void stopTunnel(
            @Param("id") @Parameter(description = "Tunnel ID", required = true)
            @PathParam("id") String id) throws ClientException;

    // ========== Connection helpers ==========

    @POST
    @Path("/_testConnection")
    @Operation(summary = "Run a staged connection diagnostic against an unsaved tunnel config")
    @MirthOperation(name = "testConnection", display = "Test SSH tunnel connection",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.SYNC)
    DiagnosticResult testConnection(
            @Param("tunnel") @Parameter(description = "Tunnel config to test; masked secrets resolve against the stored tunnel with the same ID", required = true)
            SshTunnel tunnel) throws ClientException;

    @POST
    @Path("/_fetchHostKey")
    @Operation(summary = "Fetch a server's host key for display and explicit acceptance")
    @MirthOperation(name = "fetchHostKey", display = "Fetch SSH host key",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.SYNC)
    HostKeyInfo fetchHostKey(
            @Param("host") @Parameter(description = "SSH server host", required = true)
            @QueryParam("host") String host,
            @Param("port") @Parameter(description = "SSH server port", required = true)
            @QueryParam("port") int port) throws ClientException;

    @POST
    @Path("/_derivePublicKey")
    @Operation(summary = "Derive the public key from a tunnel's private key, verifying the passphrase")
    @MirthOperation(name = "derivePublicKey", display = "Derive SSH public key",
            permission = SshTunnelPermissions.MANAGE, type = ExecuteType.SYNC)
    String derivePublicKey(
            @Param("tunnel") @Parameter(description = "Tunnel whose private key to read; masked secrets resolve against the stored tunnel with the same ID", required = true)
            SshTunnel tunnel) throws ClientException;
}
