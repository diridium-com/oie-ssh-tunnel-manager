/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Deterministic tests for the reconciler: no periodic scheduling (start() is
 * never called), a fake clock, and explicit reconcile-and-wait barriers.
 */
class TunnelManagerTest {

    private final Fakes.FakeSshConnectionFactory factory = new Fakes.FakeSshConnectionFactory();
    private final AtomicLong clock = new AtomicLong(1000);
    private TunnelManager manager;

    private TunnelManager newManager() {
        manager = new TunnelManager(factory, clock::get);
        return manager;
    }

    @AfterEach
    void tearDown() {
        if (manager != null) {
            manager.shutdown();
        }
    }

    private TunnelState stateOf(String id) {
        return manager.getStatuses().stream()
                .filter(s -> s.getTunnelId().equals(id))
                .map(SshTunnelStatus::getState)
                .findFirst()
                .orElse(null);
    }

    @Test
    void connectsEnabledTunnel() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();

        assertEquals(1, factory.openCount.get());
        assertEquals(TunnelState.CONNECTED, stateOf("t1"));
    }

    @Test
    void doesNotConnectDisabledTunnel() throws Exception {
        newManager();
        var tunnel = Fakes.passwordTunnel("t1", "vendor");
        tunnel.setEnabled(false);

        manager.applyTunnels(List.of(tunnel));
        manager.drainTasks();

        assertEquals(0, factory.openCount.get());
        assertEquals(TunnelState.DISABLED, stateOf("t1"));
    }

    @Test
    void reconnectsAfterConnectionDrops() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        assertEquals(1, factory.openCount.get());

        // Simulate the session dropping; JSch would just start reporting !isConnected.
        factory.opened.get(0).connected = false;
        manager.reconcileNowAndWait();

        // A fresh connection is opened, re-establishing all forwards.
        assertEquals(2, factory.openCount.get());
        assertEquals(TunnelState.CONNECTED, stateOf("t1"));
    }

    @Test
    void backsOffAfterFailedConnect() throws Exception {
        newManager();
        factory.failOpen = true;

        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        assertEquals(1, factory.openCount.get());
        assertEquals(TunnelState.FAILED, stateOf("t1"));

        // nextRetryAt = 1000 + backoff(1) = 6000. Before it, no new attempt.
        clock.set(5999);
        manager.reconcileNowAndWait();
        assertEquals(1, factory.openCount.get());

        // At/after nextRetryAt, it retries.
        clock.set(6000);
        manager.reconcileNowAndWait();
        assertEquals(2, factory.openCount.get());
    }

    @Test
    void recoversAfterTransientFailure() throws Exception {
        newManager();
        factory.failOpen = true;
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        assertEquals(TunnelState.FAILED, stateOf("t1"));

        factory.failOpen = false;
        clock.set(1_000_000);
        manager.reconcileNowAndWait();
        assertEquals(TunnelState.CONNECTED, stateOf("t1"));
    }

    @Test
    void stopThenStart() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        var firstConnection = factory.opened.get(0);

        manager.stopTunnel("t1");
        manager.drainTasks();
        assertTrue(firstConnection.closed, "stop should close the live connection");
        assertEquals(TunnelState.DISCONNECTED, stateOf("t1"));

        manager.startTunnel("t1");
        manager.drainTasks();
        assertEquals(2, factory.openCount.get());
        assertEquals(TunnelState.CONNECTED, stateOf("t1"));
    }

    @Test
    void configChangeTearsDownAndRebuilds() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        var firstConnection = factory.opened.get(0);

        var changed = Fakes.passwordTunnel("t1", "vendor");
        changed.setHost("new-host.example.com");
        manager.applyTunnels(List.of(changed));
        manager.drainTasks();

        assertTrue(firstConnection.closed, "old connection should be closed on config change");
        assertEquals(2, factory.openCount.get());
        assertEquals("new-host.example.com", factory.openedWith.get(1).getHost());
    }

    @Test
    void unchangedConfigDoesNotReconnect() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();

        // Re-applying an identical config should not tear down a healthy tunnel.
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();

        assertEquals(1, factory.openCount.get());
        assertFalse(factory.opened.get(0).closed);
    }

    @Test
    void removingTunnelClosesIt() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        var connection = factory.opened.get(0);

        manager.applyTunnels(List.of());
        manager.drainTasks();

        assertTrue(connection.closed);
        assertTrue(manager.getStatuses().isEmpty());
    }

    @Test
    void isActiveReflectsConnectionState() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        assertTrue(manager.isActive("t1"));

        manager.stopTunnel("t1");
        manager.drainTasks();
        assertFalse(manager.isActive("t1"));
        assertFalse(manager.isActive("no-such-id"));
    }

    @Test
    void shutdownClosesLiveConnections() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        var connection = factory.opened.get(0);

        manager.shutdown();
        assertTrue(connection.closed, "shutdown must close live connections");

        // Idempotent: a second shutdown is safe.
        manager.shutdown();
    }

    @Test
    void postAfterShutdownIsSilentlyDropped() {
        newManager();
        manager.shutdown();
        // Must not throw RejectedExecutionException out of a caller (e.g. an
        // in-flight servlet request during server stop).
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.startTunnel("t1");
        manager.stopTunnel("t1");
    }

    @Test
    void recordsConnectionEvents() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();

        var afterConnect = manager.getEvents("t1");
        assertTrue(afterConnect.stream().anyMatch(e -> e.getMessage().startsWith("Connected")),
                "expected a Connected event, got " + afterConnect);

        manager.stopTunnel("t1");
        manager.drainTasks();
        assertTrue(manager.getEvents("t1").stream().anyMatch(e -> e.getMessage().equals("Stopped")));
    }

    @Test
    void recordsFailureEvents() throws Exception {
        newManager();
        factory.failOpen = true;
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();

        assertTrue(manager.getEvents("t1").stream()
                .anyMatch(e -> e.getLevel() == com.diridium.oie.sshtunnel.TunnelEvent.Level.ERROR
                        && e.getMessage().contains("failed")));
    }

    @Test
    void removingTunnelClearsItsEvents() throws Exception {
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();
        assertFalse(manager.getEvents("t1").isEmpty());

        manager.applyTunnels(List.of());
        manager.drainTasks();
        assertTrue(manager.getEvents("t1").isEmpty());
    }

    @Test
    void statusesAndEventsDeserializeUnderClientAllowlist() throws Exception {
        // Reproduces the Administrator's wire path: a deny-by-default XStream that
        // allows only ArrayList + this plugin's types. Immutable collections
        // (List.of/List.copyOf) serialize as java.util.CollSer, which is NOT
        // allow-listed, so the client throws ForbiddenClassException and every
        // tunnel falls back to "Disconnected". This is exactly that bug's guard.
        newManager();
        manager.applyTunnels(List.of(Fakes.passwordTunnel("t1", "vendor")));
        manager.drainTasks();

        assertRoundTrips(manager.getStatuses());       // populated -> was List.copyOf
        assertRoundTrips(manager.getEvents("t1"));      // populated
        assertRoundTrips(manager.getEvents("no-such")); // empty -> was List.of()
    }

    private static void assertRoundTrips(Object value) {
        // Mirror the Administrator's XStream: deny-by-default, but allow the
        // Collection hierarchy and interfaces (ArrayList, List, ...). CollSer, the
        // immutable-collection serialization proxy, is none of those, so it fails.
        var xs = new com.thoughtworks.xstream.XStream(new com.thoughtworks.xstream.io.xml.DomDriver());
        xs.addPermission(com.thoughtworks.xstream.security.NoTypePermission.NONE);
        xs.addPermission(com.thoughtworks.xstream.security.NullPermission.NULL);
        xs.addPermission(com.thoughtworks.xstream.security.PrimitiveTypePermission.PRIMITIVES);
        xs.allowTypeHierarchy(String.class);
        xs.allowTypeHierarchy(java.util.Collection.class);
        xs.allowTypesByWildcard(new String[] {"com.diridium.oie.sshtunnel.**"});
        var xml = xs.toXML(value);
        assertTrue(xs.fromXML(xml) != null, "should deserialize without ForbiddenClassException");
    }

    @Test
    void backoffDelayGrowsAndCaps() {
        assertEquals(5000L, TunnelManager.backoffDelay(1));
        assertEquals(10000L, TunnelManager.backoffDelay(2));
        assertEquals(20000L, TunnelManager.backoffDelay(3));
        assertEquals(TunnelManager.BACKOFF_MAX_MS, TunnelManager.backoffDelay(20));
    }
}
