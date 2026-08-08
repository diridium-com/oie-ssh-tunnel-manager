/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Keeps enabled tunnels connected.
 *
 * All state is owned by a single-threaded scheduled executor: the periodic
 * reconcile pass and every mutation (config apply, start, stop, shutdown) run
 * as tasks on that one thread, so there is no locking. Status reads come from a
 * volatile immutable snapshot refreshed whenever state changes.
 *
 * JSch has no disconnect callback, so the reconcile pass polls
 * {@link SshConnection#isConnected()} and re-establishes dropped sessions with
 * exponential backoff. Forwards do not survive a reconnect in JSch; reopening
 * the connection re-establishes all of them.
 */
public class TunnelManager {

    private static final Logger log = LoggerFactory.getLogger(TunnelManager.class);

    static final long RECONCILE_INTERVAL_MS = 5000;
    static final long BACKOFF_BASE_MS = 5000;
    static final long BACKOFF_MAX_MS = 300000;
    // Longer than a single connect attempt (JschConnectionFactory's 15s) plus
    // margin, so a shutdown that lands during an in-flight connect still waits
    // for the clean-close task rather than discarding it.
    static final long SHUTDOWN_WAIT_MS = 20000;

    private final SshConnectionFactory factory;
    private final LongSupplier clock;
    private final ScheduledExecutorService executor;

    static final int MAX_EVENTS_PER_TUNNEL = 100;

    /** Only touched on the executor thread. */
    private final Map<String, TunnelRuntime> runtimes = new LinkedHashMap<>();

    /**
     * Per-tunnel rolling event history. Written on the executor thread, read
     * from servlet threads, so the map and its deques are concurrent.
     */
    private final Map<String, Deque<TunnelEvent>> eventLog = new ConcurrentHashMap<>();

    private volatile List<SshTunnelStatus> statusSnapshot = List.of();

    /** Set once shutdown begins; stops any later reconcile from reopening tunnels. */
    private volatile boolean closed;

    public TunnelManager(SshConnectionFactory factory) {
        this(factory, System::currentTimeMillis);
    }

    TunnelManager(SshConnectionFactory factory, LongSupplier clock) {
        this.factory = factory;
        this.clock = clock;
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
            var t = new Thread(r, "ssh-tunnel-reconciler");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() {
        executor.scheduleWithFixedDelay(this::safeReconcile, RECONCILE_INTERVAL_MS,
                RECONCILE_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    /** Replaces the desired configuration. Changed tunnels are torn down and rebuilt. */
    public void applyTunnels(List<SshTunnel> tunnels) {
        var copies = new ArrayList<SshTunnel>(tunnels.size());
        for (var tunnel : tunnels) {
            copies.add(tunnel.copy());
        }
        post(() -> {
            applyOnThread(copies);
            reconcile();
        });
    }

    /** Clears a manual stop and retries immediately. */
    public void startTunnel(String id) {
        post(() -> {
            var runtime = runtimes.get(id);
            if (runtime != null) {
                runtime.suspended = false;
                runtime.failedAttempts = 0;
                runtime.nextRetryAt = 0;
                reconcile();
            }
        });
    }

    /** Manually stops a tunnel until startTunnel or a config change. */
    public void stopTunnel(String id) {
        post(() -> {
            var runtime = runtimes.get(id);
            if (runtime != null) {
                runtime.suspended = true;
                reconcile();
            }
        });
    }

    public List<SshTunnelStatus> getStatuses() {
        return statusSnapshot;
    }

    /** True when the tunnel currently holds a live connection (its forwards are bound). */
    public boolean isActive(String id) {
        for (var status : statusSnapshot) {
            if (status.getTunnelId().equals(id)) {
                return status.getState() == TunnelState.CONNECTED;
            }
        }
        return false;
    }

    /** Recent connection-history events for a tunnel, oldest first. */
    public List<TunnelEvent> getEvents(String id) {
        var deque = eventLog.get(id);
        return deque == null ? List.of() : new ArrayList<>(deque);
    }

    private void recordEvent(String id, TunnelEvent.Level level, String message) {
        var deque = eventLog.computeIfAbsent(id, k -> new ConcurrentLinkedDeque<>());
        deque.addLast(new TunnelEvent(clock.getAsLong(), level, message));
        while (deque.size() > MAX_EVENTS_PER_TUNNEL) {
            deque.pollFirst();
        }
    }

    /**
     * Posts a task to the reconciler thread, tolerating a shut-down executor.
     * After shutdown the desired state is already persisted and will be applied
     * on next start, so dropping the post is correct rather than surfacing a
     * RejectedExecutionException out of an in-flight request.
     */
    private void post(Runnable task) {
        try {
            executor.execute(task);
        } catch (RejectedExecutionException e) {
            log.debug("Ignoring tunnel task; manager is shutting down");
        }
    }

    public void shutdown() {
        // Mark closed first so any reconcile still in flight (or one that fires
        // in the gap before shutdownNow lands) will not reopen a tunnel.
        closed = true;
        try {
            executor.submit(this::closeAllOnThread).get(SHUTDOWN_WAIT_MS, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            log.warn("Timed out waiting for tunnels to close; closing remaining from caller: {}", e.getMessage());
        }
        executor.shutdownNow();
        try {
            executor.awaitTermination(SHUTDOWN_WAIT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // The executor thread is gone now, so this is the only thread touching
        // the runtimes; close anything the discarded close task left open
        // (e.g. a connection opened by an attempt that completed after the
        // wait timed out).
        closeAllOnThread();
    }

    // ------------------------------------------------------------------
    // Everything below runs on the executor thread only.
    // ------------------------------------------------------------------

    private void applyOnThread(List<SshTunnel> tunnels) {
        var incomingIds = new HashSet<String>();
        for (var tunnel : tunnels) {
            incomingIds.add(tunnel.getId());
        }

        var removedIds = new HashSet<>(runtimes.keySet());
        removedIds.removeAll(incomingIds);
        for (var id : removedIds) {
            var runtime = runtimes.remove(id);
            closeQuietly(runtime);
            eventLog.remove(id);
            log.info("Tunnel '{}' removed", runtime.config.getName());
        }

        for (var tunnel : tunnels) {
            var runtime = runtimes.get(tunnel.getId());
            if (runtime == null) {
                runtimes.put(tunnel.getId(), new TunnelRuntime(tunnel));
            } else if (!runtime.config.equals(tunnel)) {
                closeQuietly(runtime);
                runtime.config = tunnel;
                runtime.suspended = false;
                runtime.failedAttempts = 0;
                runtime.nextRetryAt = 0;
                runtime.lastError = "";
                log.info("Tunnel '{}' configuration changed; reconnecting", tunnel.getName());
                recordEvent(tunnel.getId(), TunnelEvent.Level.INFO, "Configuration changed; reconnecting");
            }
        }
    }

    private void safeReconcile() {
        try {
            reconcile();
        } catch (Exception e) {
            log.error("Reconcile pass failed", e);
        }
    }

    private void reconcile() {
        if (closed) {
            return;
        }
        for (var runtime : runtimes.values()) {
            reconcileOne(runtime);
        }
        updateSnapshot();
    }

    private void reconcileOne(TunnelRuntime runtime) {
        var wantConnected = runtime.config.isEnabled() && !runtime.suspended;

        if (!wantConnected) {
            if (runtime.connection != null) {
                closeQuietly(runtime);
                log.info("Tunnel '{}' stopped", runtime.config.getName());
                recordEvent(runtime.config.getId(), TunnelEvent.Level.INFO, "Stopped");
            }
            runtime.state = runtime.config.isEnabled() ? TunnelState.DISCONNECTED : TunnelState.DISABLED;
            runtime.nextRetryAt = 0;
            return;
        }

        if (runtime.connection != null) {
            if (runtime.connection.isConnected()) {
                runtime.state = TunnelState.CONNECTED;
                return;
            }
            // Dropped since the last pass: retry immediately, then back off.
            closeQuietly(runtime);
            runtime.lastError = "Connection lost";
            runtime.failedAttempts = 0;
            runtime.nextRetryAt = 0;
            log.warn("Tunnel '{}' lost its connection", runtime.config.getName());
            recordEvent(runtime.config.getId(), TunnelEvent.Level.WARN, "Connection lost; reconnecting");
        }

        var now = clock.getAsLong();
        if (now < runtime.nextRetryAt) {
            return;
        }

        runtime.state = runtime.failedAttempts == 0 && runtime.lastError.isEmpty()
                ? TunnelState.CONNECTING : TunnelState.RECONNECTING;
        updateSnapshot();

        try {
            runtime.connection = factory.open(runtime.config);
            runtime.state = TunnelState.CONNECTED;
            runtime.connectedSince = clock.getAsLong();
            runtime.failedAttempts = 0;
            runtime.nextRetryAt = 0;
            runtime.lastError = "";
            recordEvent(runtime.config.getId(), TunnelEvent.Level.INFO,
                    "Connected to " + runtime.config.getEndpointDescription()
                            + " (" + runtime.config.getForwards().size() + " forward(s))");
        } catch (Exception e) {
            runtime.connection = null;
            runtime.connectedSince = 0;
            runtime.failedAttempts++;
            runtime.lastError = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            runtime.nextRetryAt = clock.getAsLong() + backoffDelay(runtime.failedAttempts);
            runtime.state = TunnelState.FAILED;
            log.warn("Tunnel '{}' connection attempt {} failed: {}",
                    runtime.config.getName(), runtime.failedAttempts, runtime.lastError);
            recordEvent(runtime.config.getId(), TunnelEvent.Level.ERROR,
                    "Attempt " + runtime.failedAttempts + " failed: " + runtime.lastError);
        }
    }

    static long backoffDelay(int failedAttempts) {
        var exponent = Math.min(failedAttempts - 1, 10);
        return Math.min(BACKOFF_BASE_MS << exponent, BACKOFF_MAX_MS);
    }

    private void closeAllOnThread() {
        for (var runtime : runtimes.values()) {
            closeQuietly(runtime);
            runtime.state = TunnelState.DISCONNECTED;
        }
        updateSnapshot();
    }

    private void closeQuietly(TunnelRuntime runtime) {
        if (runtime.connection != null) {
            runtime.connection.close();
            runtime.connection = null;
        }
        runtime.connectedSince = 0;
    }

    private void updateSnapshot() {
        var statuses = new ArrayList<SshTunnelStatus>(runtimes.size());
        for (var runtime : runtimes.values()) {
            var status = new SshTunnelStatus(runtime.config.getId(), runtime.state);
            status.setLastError(runtime.lastError);
            status.setConnectedSince(runtime.connectedSince);
            status.setFailedAttempts(runtime.failedAttempts);
            status.setNextRetryAt(runtime.nextRetryAt);
            statuses.add(status);
        }
        statusSnapshot = List.copyOf(statuses);
    }

    /** Test hook: runs a reconcile pass on the executor thread and waits for it. */
    void reconcileNowAndWait() throws Exception {
        executor.submit(this::reconcile).get(30, TimeUnit.SECONDS);
    }

    /** Test hook: waits until previously submitted tasks have drained. */
    void drainTasks() throws Exception {
        executor.submit(() -> { }).get(30, TimeUnit.SECONDS);
    }

    private static class TunnelRuntime {

        SshTunnel config;
        SshConnection connection;
        boolean suspended;
        TunnelState state;
        String lastError = "";
        long connectedSince;
        int failedAttempts;
        long nextRetryAt;

        TunnelRuntime(SshTunnel config) {
            this.config = config;
            this.state = config.isEnabled() ? TunnelState.DISCONNECTED : TunnelState.DISABLED;
        }
    }
}
