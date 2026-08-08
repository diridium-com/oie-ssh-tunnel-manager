/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Service-level tests: CRUD, secret masking on the wire, encryption at rest,
 * the persist/reload round-trip through the private XStream, and validation.
 * Uses fakes so no engine controllers and no real SSH are required.
 */
class SshTunnelServiceTest {

    private final List<TunnelManager> managers = new ArrayList<>();
    private TunnelManager lastManager;

    @AfterEach
    void tearDown() {
        managers.forEach(TunnelManager::shutdown);
    }

    private SshTunnelService newService(Fakes.FakeConfigStore store, Fakes.FakeSshConnectionFactory factory) {
        lastManager = new TunnelManager(factory, System::currentTimeMillis);
        managers.add(lastManager);
        return new SshTunnelService(store, lastManager, factory);
    }

    /** A password tunnel whose single local forward binds a distinct port (avoids collision checks). */
    private static SshTunnel tunnelOnPort(String name, int localPort) {
        var tunnel = Fakes.passwordTunnel(null, name);
        tunnel.getForwards().get(0).setBindPort(localPort);
        return tunnel;
    }

    @Test
    void createAssignsIdMasksSecretAndEncryptsAtRest() {
        var store = new Fakes.FakeConfigStore();
        var service = newService(store, new Fakes.FakeSshConnectionFactory());

        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));

        assertNotNull(created.getId());
        assertEquals(SshTunnel.SECRET_MASK, created.getPassword(), "returned password must be masked");

        var persisted = store.getProperty("tunnels");
        assertNotNull(persisted);
        assertTrue(persisted.contains("ENC[s3cret]"), "password must be encrypted at rest");
        assertFalse(persisted.contains(">s3cret<"), "plaintext password must not be persisted");
    }

    @Test
    void getTunnelsMasksAllSecrets() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        service.create(Fakes.passwordTunnel(null, "vendor-a"));

        var tunnels = service.getTunnelsMasked();
        assertEquals(1, tunnels.size());
        assertEquals(SshTunnel.SECRET_MASK, tunnels.get(0).getPassword());
    }

    @Test
    void updateWithMaskedSecretKeepsStoredValue() {
        var store = new Fakes.FakeConfigStore();
        var service = newService(store, new Fakes.FakeSshConnectionFactory());
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));

        // Client sends back the masked value it received.
        var edit = service.getTunnelsMasked().get(0);
        edit.setUsername("changed-user");
        assertEquals(SshTunnel.SECRET_MASK, edit.getPassword());
        service.update(created.getId(), edit);

        assertTrue(store.getProperty("tunnels").contains("ENC[s3cret]"),
                "stored password should be preserved when the client sends the mask");
        assertTrue(store.getProperty("tunnels").contains("changed-user"));
    }

    @Test
    void updateWithNewSecretReplacesStoredValue() {
        var store = new Fakes.FakeConfigStore();
        var service = newService(store, new Fakes.FakeSshConnectionFactory());
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));

        var edit = service.getTunnelsMasked().get(0);
        edit.setPassword("rotated-pw");
        service.update(created.getId(), edit);

        assertTrue(store.getProperty("tunnels").contains("ENC[rotated-pw]"));
        assertFalse(store.getProperty("tunnels").contains("ENC[s3cret]"));
    }

    @Test
    void rejectsLocalForwardPortCollisionAcrossTunnels() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        service.create(Fakes.passwordTunnel(null, "vendor-a")); // local 127.0.0.1:6661
        var b = Fakes.passwordTunnel(null, "vendor-b");           // also 127.0.0.1:6661
        var ex = assertThrows(IllegalArgumentException.class, () -> service.create(b));
        assertTrue(ex.getMessage().contains("vendor-a"), ex.getMessage());
    }

    @Test
    void allowsDifferentLocalPorts() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        service.create(Fakes.passwordTunnel(null, "vendor-a"));
        var b = Fakes.passwordTunnel(null, "vendor-b");
        b.getForwards().get(0).setBindPort(6662);
        assertDoesNotThrow(() -> service.create(b));
    }

    @Test
    void rejectsDuplicateLocalBindWithinOneTunnel() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        var t = Fakes.passwordTunnel(null, "vendor");
        t.getForwards().add(new PortForward(ForwardDirection.LOCAL, "127.0.0.1", 6661, "other", 9000));
        var ex = assertThrows(IllegalArgumentException.class, () -> service.create(t));
        assertTrue(ex.getMessage().contains("same address"), ex.getMessage());
    }

    @Test
    void updatingATunnelDoesNotCollideWithItself() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));
        var edit = service.getTunnelsMasked().get(0);
        edit.setName("vendor-a renamed");
        // Same forward (127.0.0.1:6661) must not collide against its own stored copy.
        assertDoesNotThrow(() -> service.update(created.getId(), edit));
    }

    @Test
    void duplicateNameRejected() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        service.create(Fakes.passwordTunnel(null, "vendor-a"));

        var ex = assertThrows(IllegalArgumentException.class,
                () -> service.create(Fakes.passwordTunnel(null, "VENDOR-A")));
        assertTrue(ex.getMessage().contains("already exists"));
    }

    @Test
    void deleteRemovesAndPersists() {
        var store = new Fakes.FakeConfigStore();
        var service = newService(store, new Fakes.FakeSshConnectionFactory());
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));

        service.delete(created.getId());
        assertTrue(service.getTunnelsMasked().isEmpty());
        assertThrows(NoSuchElementException.class, () -> service.delete(created.getId()));
    }

    @Test
    void validationRejectsMissingFields() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());

        var noHost = Fakes.passwordTunnel(null, "bad");
        noHost.setHost("");
        assertThrows(IllegalArgumentException.class, () -> service.create(noHost));

        var badForwardPort = Fakes.passwordTunnel(null, "bad2");
        badForwardPort.getForwards().get(0).setBindPort(0);
        assertThrows(IllegalArgumentException.class, () -> service.create(badForwardPort));
    }

    @Test
    void verifyHostKeyWithoutAcceptedKeyRejected() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        var tunnel = Fakes.passwordTunnel(null, "strict");
        tunnel.setVerifyHostKey(true);
        tunnel.setAcceptedHostKey("");

        var ex = assertThrows(IllegalArgumentException.class, () -> service.create(tunnel));
        assertTrue(ex.getMessage().contains("host key"));
    }

    @Test
    void persistReloadRoundTrip() {
        var store = new Fakes.FakeConfigStore();
        var serviceA = newService(store, new Fakes.FakeSshConnectionFactory());
        serviceA.create(tunnelOnPort("vendor-a", 6661));
        serviceA.create(tunnelOnPort("vendor-b", 6662));

        // A brand-new service over the same store must reload both tunnels,
        // decrypting their secrets back to plaintext internally.
        var serviceB = newService(store, new Fakes.FakeSshConnectionFactory());
        serviceB.load();

        var reloaded = serviceB.getTunnelsMasked();
        assertEquals(2, reloaded.size());
        assertTrue(reloaded.stream().anyMatch(t -> t.getName().equals("vendor-a")));
        assertTrue(reloaded.stream().anyMatch(t -> t.getName().equals("vendor-b")));
        // Re-persisting must not double-encrypt.
        serviceB.create(tunnelOnPort("vendor-c", 6663));
        assertFalse(store.getProperty("tunnels").contains("ENC[ENC["));
    }

    @Test
    void loadFailureMakesServiceRefuseToPersist() {
        var store = new Fakes.FakeConfigStore();
        // Seed unreadable data, then force decrypt to fail during load.
        store.saveProperty("tunnels", "not valid xml at all");
        var service = newService(store, new Fakes.FakeSshConnectionFactory());
        service.load();

        // Refuse to overwrite data we could not read.
        assertThrows(IllegalStateException.class,
                () -> service.create(Fakes.passwordTunnel(null, "vendor-a")));
    }

    @Test
    void testConnectionReportsSuccessAndFailure() {
        var factory = new Fakes.FakeSshConnectionFactory();
        var service = newService(new Fakes.FakeConfigStore(), factory);

        var ok = service.testConnection(Fakes.passwordTunnel(null, "vendor-a"));
        assertTrue(ok.isSuccess(), ok.getSummary());
        assertFalse(ok.getSteps().isEmpty());

        factory.failOpen = true;
        var bad = service.testConnection(Fakes.passwordTunnel(null, "vendor-a"));
        assertFalse(bad.isSuccess(), bad.getSummary());
    }

    @Test
    void testConnectionValidationFailureReturnsDiagnosticStep() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        var noHost = Fakes.passwordTunnel(null, "bad");
        noHost.setHost("");

        var result = service.testConnection(noHost);
        assertFalse(result.isSuccess());
        assertEquals(StepStatus.FAIL, result.getSteps().get(0).getStatus());
        assertEquals("Validation", result.getSteps().get(0).getName());
    }

    @Test
    void testConnectionResolvesMaskedSecretAgainstStoredTunnel() {
        var factory = new Fakes.FakeSshConnectionFactory();
        var service = newService(new Fakes.FakeConfigStore(), factory);
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));

        // Client tests an edited-but-unsaved tunnel that still carries the mask.
        var edit = service.getTunnelsMasked().get(0);
        edit.setId(created.getId());
        service.testConnection(edit);

        // The factory must have received the real stored password, not the mask.
        var used = factory.openedWith.get(factory.openedWith.size() - 1);
        assertEquals("s3cret", used.getPassword());
    }

    @Test
    void testConnectionOfLiveTunnelPassesAlreadyLiveToDiagnose() throws Exception {
        var factory = new Fakes.FakeSshConnectionFactory();
        var service = newService(new Fakes.FakeConfigStore(), factory);
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));
        // create() posts applyTunnels to the manager; drive it so the tunnel connects.
        lastManager.drainTasks();
        assertTrue(lastManager.isActive(created.getId()));

        var edit = service.getTunnelsMasked().get(0);
        edit.setId(created.getId());
        service.testConnection(edit);

        // The diagnostic must know the tunnel is live so it skips re-binding remote forwards.
        assertEquals(Boolean.TRUE, factory.lastDiagnoseAlreadyLive);
        assertEquals(1, factory.diagnoseCount.get());
    }

    @Test
    void getEventsReturnsManagerEventsAndValidatesId() throws Exception {
        var factory = new Fakes.FakeSshConnectionFactory();
        var service = newService(new Fakes.FakeConfigStore(), factory);
        var created = service.create(Fakes.passwordTunnel(null, "vendor-a"));
        lastManager.drainTasks();

        // Connecting recorded at least one event.
        assertFalse(service.getEvents(created.getId()).isEmpty());
        assertThrows(NoSuchElementException.class, () -> service.getEvents("no-such-id"));
    }

    @Test
    void derivePublicKeyResolvesMaskAndReturnsKey() throws Exception {
        var factory = new Fakes.FakeSshConnectionFactory();
        factory.derivedPublicKey = "ssh-ed25519 AAAATEST oie-tunnel";
        var service = newService(new Fakes.FakeConfigStore(), factory);

        var keyTunnel = Fakes.passwordTunnel(null, "vendor");
        keyTunnel.setAuthMethod(AuthMethod.PRIVATE_KEY);
        keyTunnel.setKeySource(KeySource.INLINE);
        keyTunnel.setPrivateKeyPem("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----");
        var created = service.create(keyTunnel);

        // Client re-derives from an edited tunnel still carrying the masked key.
        var edit = service.getTunnelsMasked().get(0);
        edit.setId(created.getId());
        assertEquals("ssh-ed25519 AAAATEST oie-tunnel", service.derivePublicKey(edit));
    }

    @Test
    void derivePublicKeyPropagatesDecryptFailure() {
        var factory = new Fakes.FakeSshConnectionFactory();
        factory.failDerive = true;
        var service = newService(new Fakes.FakeConfigStore(), factory);
        var keyTunnel = Fakes.passwordTunnel(null, "vendor");
        keyTunnel.setAuthMethod(AuthMethod.PRIVATE_KEY);
        keyTunnel.setKeySource(KeySource.INLINE);
        keyTunnel.setPrivateKeyPem("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----");
        assertThrows(SshTunnelException.class, () -> service.derivePublicKey(keyTunnel));
    }

    @Test
    void fetchHostKeyValidatesInputs() {
        var service = newService(new Fakes.FakeConfigStore(), new Fakes.FakeSshConnectionFactory());
        assertThrows(IllegalArgumentException.class, () -> service.fetchHostKey("", 22));
        assertThrows(IllegalArgumentException.class, () -> service.fetchHostKey("host", 0));
    }
}
