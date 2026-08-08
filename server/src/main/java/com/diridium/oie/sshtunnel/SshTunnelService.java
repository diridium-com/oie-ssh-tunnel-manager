/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Business logic and persistence for tunnel configurations.
 *
 * The canonical tunnel list lives here in memory with plaintext secrets (the
 * connection factory needs them); at rest secrets are encrypted, on the wire to
 * the client they are masked. Every mutation persists the full list and pushes
 * the desired state to the {@link TunnelManager}.
 */
public class SshTunnelService {

    private static final Logger log = LoggerFactory.getLogger(SshTunnelService.class);
    private static final String PROPERTY_TUNNELS = "tunnels";

    private static volatile SshTunnelService instance;

    private final ConfigStore store;
    private final TunnelManager manager;
    private final SshConnectionFactory factory;
    private final List<SshTunnel> tunnels = new ArrayList<>();
    private boolean loadFailed;

    public SshTunnelService(ConfigStore store, TunnelManager manager, SshConnectionFactory factory) {
        this.store = store;
        this.manager = manager;
        this.factory = factory;
    }

    public static synchronized void init(SshTunnelService service) {
        // Publish the instance LAST. Doing it first would let a request that
        // reaches the servlet mid-startup operate on a not-yet-loaded service,
        // whose create() would persist a one-element list over the stored
        // config, and would also leave load()'s writes without a happens-before
        // edge to reader threads.
        service.load();
        service.manager.start();
        service.manager.applyTunnels(service.snapshot());
        instance = service;
    }

    public static SshTunnelService getInstance() {
        var current = instance;
        if (current == null) {
            throw new IllegalStateException("SSH Tunnel Manager service not initialized");
        }
        return current;
    }

    public static synchronized void shutdown() {
        var current = instance;
        if (current != null) {
            current.manager.shutdown();
            instance = null;
        }
    }

    // ------------------------------------------------------------------
    // CRUD
    // ------------------------------------------------------------------

    public synchronized List<SshTunnel> getTunnelsMasked() {
        var masked = new ArrayList<SshTunnel>(tunnels.size());
        for (var tunnel : tunnels) {
            masked.add(SecretFields.mask(tunnel));
        }
        return masked;
    }

    public synchronized SshTunnel create(SshTunnel incoming) {
        var tunnel = SecretFields.resolveMasks(incoming, null);
        if (tunnel.getId() == null || tunnel.getId().isBlank()) {
            tunnel.setId(UUID.randomUUID().toString());
        }
        validate(tunnel, null);
        tunnels.add(tunnel);
        persist();
        manager.applyTunnels(snapshot());
        return SecretFields.mask(tunnel);
    }

    public synchronized SshTunnel update(String id, SshTunnel incoming) {
        var stored = findById(id);
        var tunnel = SecretFields.resolveMasks(incoming, stored);
        tunnel.setId(id);
        validate(tunnel, id);
        tunnels.set(tunnels.indexOf(stored), tunnel);
        persist();
        manager.applyTunnels(snapshot());
        return SecretFields.mask(tunnel);
    }

    public synchronized void delete(String id) {
        var stored = findById(id);
        tunnels.remove(stored);
        persist();
        manager.applyTunnels(snapshot());
    }

    public synchronized String getTunnelName(String id) {
        return findById(id).getName();
    }

    // ------------------------------------------------------------------
    // Runtime
    // ------------------------------------------------------------------

    public List<SshTunnelStatus> getStatuses() {
        return manager.getStatuses();
    }

    public synchronized void startTunnel(String id) {
        findById(id);
        manager.startTunnel(id);
    }

    public synchronized void stopTunnel(String id) {
        findById(id);
        manager.stopTunnel(id);
    }

    /**
     * Runs a staged connection diagnostic against the given (possibly unsaved)
     * config and returns per-step results. Never throws for a connection
     * problem; failures are steps in the result so the dialog can show the whole
     * picture.
     */
    public DiagnosticResult testConnection(SshTunnel incoming) {
        SshTunnel stored;
        boolean alreadyLive;
        synchronized (this) {
            stored = incoming.getId() != null ? findByIdOrNull(incoming.getId()) : null;
            alreadyLive = incoming.getId() != null && manager.isActive(incoming.getId());
        }
        var tunnel = SecretFields.resolveMasks(incoming, stored);
        try {
            // A test never persists, so uniqueness is irrelevant; passing "" as
            // the self-id skips the uniqueness loop (which would otherwise
            // iterate the shared tunnel list off the service lock).
            validate(tunnel, "");
        } catch (IllegalArgumentException e) {
            var result = new DiagnosticResult();
            result.add("Validation", StepStatus.FAIL, e.getMessage(), 0);
            result.finish();
            return result;
        }
        return factory.diagnose(tunnel, alreadyLive);
    }

    /** Recent connection-history events for a tunnel. */
    public List<TunnelEvent> getEvents(String id) {
        synchronized (this) {
            findById(id);
        }
        return manager.getEvents(id);
    }

    public HostKeyInfo fetchHostKey(String host, int port) throws SshTunnelException {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Host is required");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 1 and 65535");
        }
        return factory.fetchHostKey(host.trim(), port);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /**
     * At-rest serialization. This blob is server-only — the client receives
     * tunnels as JSON/XML through the servlet, never this stored form — so it
     * does not go through the engine's ObjectXMLSerializer. A private XStream
     * locked to this plugin's own types keeps the persistence path free of the
     * engine's serializer dependency chain and denies deserializing anything
     * else.
     */
    private static XStream newXStream() {
        var xstream = new XStream(new DomDriver());
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        xstream.allowTypeHierarchy(String.class);
        // Only the concrete collection type the blob actually uses, rather than
        // the whole Collection hierarchy — keeps every other classpath
        // collection out of reach of a tampered store.
        xstream.allowTypes(new Class[] {java.util.ArrayList.class, java.util.List.class});
        xstream.allowTypesByWildcard(new String[] {"com.diridium.oie.sshtunnel.**"});
        xstream.alias("tunnel", SshTunnel.class);
        xstream.alias("forward", PortForward.class);
        return xstream;
    }

    void load() {
        try {
            var xml = store.getProperty(PROPERTY_TUNNELS);
            if (xml == null || xml.isBlank()) {
                return;
            }
            @SuppressWarnings("unchecked")
            var loaded = (List<SshTunnel>) newXStream().fromXML(xml);
            for (var tunnel : loaded) {
                tunnels.add(SecretFields.decrypt(tunnel, store::decrypt));
            }
            log.info("Loaded {} tunnel(s)", tunnels.size());
        } catch (Exception e) {
            // Refuse to persist over data we could not read: a save now would
            // permanently destroy every stored tunnel.
            loadFailed = true;
            log.error("Failed to load stored tunnels; tunnel management is read-only until this is fixed", e);
        }
    }

    private void persist() {
        if (loadFailed) {
            throw new IllegalStateException("Stored tunnel configuration could not be read at startup;"
                    + " refusing to overwrite it. Check the server log.");
        }
        var toStore = new ArrayList<SshTunnel>(tunnels.size());
        for (var tunnel : tunnels) {
            toStore.add(SecretFields.encrypt(tunnel, store::encrypt));
        }
        store.saveProperty(PROPERTY_TUNNELS, newXStream().toXML(toStore));
    }

    private List<SshTunnel> snapshot() {
        var copy = new ArrayList<SshTunnel>(tunnels.size());
        for (var tunnel : tunnels) {
            copy.add(tunnel.copy());
        }
        return copy;
    }

    private SshTunnel findById(String id) {
        var tunnel = findByIdOrNull(id);
        if (tunnel == null) {
            throw new NoSuchElementException("No tunnel with ID " + id);
        }
        return tunnel;
    }

    private SshTunnel findByIdOrNull(String id) {
        for (var tunnel : tunnels) {
            if (tunnel.getId().equals(id)) {
                return tunnel;
            }
        }
        return null;
    }

    /**
     * @param selfId the tunnel's own ID for uniqueness checks; null on create,
     *               empty string to skip the uniqueness check (inline test).
     */
    private void validate(SshTunnel tunnel, String selfId) {
        requireNonBlank(tunnel.getName(), "Name");
        requireNonBlank(tunnel.getHost(), "Host");
        requireNonBlank(tunnel.getUsername(), "Username");
        requirePort(tunnel.getPort(), "SSH port");

        if (tunnel.getAuthMethod() == AuthMethod.PASSWORD) {
            requireNonBlank(tunnel.getPassword(), "Password");
        } else if (tunnel.getKeySource() == KeySource.FILE) {
            requireNonBlank(tunnel.getPrivateKeyPath(), "Private key path");
        } else {
            requireNonBlank(tunnel.getPrivateKeyPem(), "Private key");
        }

        if (tunnel.isVerifyHostKey() && isBlank(tunnel.getAcceptedHostKey())) {
            throw new IllegalArgumentException("Host key verification is enabled but no host key has been"
                    + " accepted. Fetch and accept the host key, or disable verification.");
        }

        if (tunnel.getServerAliveIntervalSeconds() < 0) {
            throw new IllegalArgumentException("Keep-alive interval must be 0 (off) or positive");
        }

        for (var forward : tunnel.getForwards()) {
            requireNonBlank(forward.getBindHost(), "Forward bind host");
            requireNonBlank(forward.getDestinationHost(), "Forward destination host");
            requirePort(forward.getBindPort(), "Forward bind port");
            requirePort(forward.getDestinationPort(), "Forward destination port");
        }

        if (!"".equals(selfId)) {
            for (var other : tunnels) {
                if (!other.getId().equals(selfId) && other.getName().equalsIgnoreCase(tunnel.getName())) {
                    throw new IllegalArgumentException("A tunnel named '" + tunnel.getName() + "' already exists");
                }
            }
        }
    }

    private static void requireNonBlank(String value, String field) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    private static void requirePort(int port, String field) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException(field + " must be between 1 and 65535");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
