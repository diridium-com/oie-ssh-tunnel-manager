/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Configuration of one managed SSH tunnel: an SSH endpoint, credentials, and a
 * set of port forwards kept alive while the tunnel is enabled.
 *
 * Secret fields (password, privateKeyPem, privateKeyPassphrase) are encrypted
 * at rest on the server and replaced with {@link #SECRET_MASK} before being
 * sent to the client. A client sending the mask back means "keep the stored
 * value".
 */
public class SshTunnel implements Serializable {

    /** Placeholder the server returns instead of a stored secret. */
    public static final String SECRET_MASK = "********";

    private String id;
    private String name = "";
    private boolean enabled = true;

    private String host = "";
    private int port = 22;
    private String username = "";

    private AuthMethod authMethod = AuthMethod.PASSWORD;
    private String password = "";

    private KeySource keySource = KeySource.FILE;
    private String privateKeyPath = "";
    private String privateKeyPem = "";
    private String privateKeyPassphrase = "";

    private boolean verifyHostKey = true;
    /** Base64 public key blob accepted by the admin (the wire-format key, not a fingerprint). */
    private String acceptedHostKey = "";
    /** Key algorithm of the accepted host key, e.g. ssh-ed25519. */
    private String acceptedHostKeyType = "";

    private int serverAliveIntervalSeconds = 30;
    private int serverAliveCountMax = 3;

    private List<PortForward> forwards = new ArrayList<>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public AuthMethod getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(AuthMethod authMethod) {
        this.authMethod = authMethod;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public KeySource getKeySource() {
        return keySource;
    }

    public void setKeySource(KeySource keySource) {
        this.keySource = keySource;
    }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public String getPrivateKeyPem() {
        return privateKeyPem;
    }

    public void setPrivateKeyPem(String privateKeyPem) {
        this.privateKeyPem = privateKeyPem;
    }

    public String getPrivateKeyPassphrase() {
        return privateKeyPassphrase;
    }

    public void setPrivateKeyPassphrase(String privateKeyPassphrase) {
        this.privateKeyPassphrase = privateKeyPassphrase;
    }

    public boolean isVerifyHostKey() {
        return verifyHostKey;
    }

    public void setVerifyHostKey(boolean verifyHostKey) {
        this.verifyHostKey = verifyHostKey;
    }

    public String getAcceptedHostKey() {
        return acceptedHostKey;
    }

    public void setAcceptedHostKey(String acceptedHostKey) {
        this.acceptedHostKey = acceptedHostKey;
    }

    public String getAcceptedHostKeyType() {
        return acceptedHostKeyType;
    }

    public void setAcceptedHostKeyType(String acceptedHostKeyType) {
        this.acceptedHostKeyType = acceptedHostKeyType;
    }

    public int getServerAliveIntervalSeconds() {
        return serverAliveIntervalSeconds;
    }

    public void setServerAliveIntervalSeconds(int serverAliveIntervalSeconds) {
        this.serverAliveIntervalSeconds = serverAliveIntervalSeconds;
    }

    public int getServerAliveCountMax() {
        return serverAliveCountMax;
    }

    public void setServerAliveCountMax(int serverAliveCountMax) {
        this.serverAliveCountMax = serverAliveCountMax;
    }

    public List<PortForward> getForwards() {
        return forwards;
    }

    public void setForwards(List<PortForward> forwards) {
        this.forwards = forwards != null ? forwards : new ArrayList<>();
    }

    public String getEndpointDescription() {
        return username + "@" + host + ":" + port;
    }

    public SshTunnel copy() {
        var copy = new SshTunnel();
        copy.id = id;
        copy.name = name;
        copy.enabled = enabled;
        copy.host = host;
        copy.port = port;
        copy.username = username;
        copy.authMethod = authMethod;
        copy.password = password;
        copy.keySource = keySource;
        copy.privateKeyPath = privateKeyPath;
        copy.privateKeyPem = privateKeyPem;
        copy.privateKeyPassphrase = privateKeyPassphrase;
        copy.verifyHostKey = verifyHostKey;
        copy.acceptedHostKey = acceptedHostKey;
        copy.acceptedHostKeyType = acceptedHostKeyType;
        copy.serverAliveIntervalSeconds = serverAliveIntervalSeconds;
        copy.serverAliveCountMax = serverAliveCountMax;
        copy.forwards = new ArrayList<>();
        for (var forward : forwards) {
            copy.forwards.add(forward.copy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SshTunnel other)) {
            return false;
        }
        return enabled == other.enabled
                && port == other.port
                && verifyHostKey == other.verifyHostKey
                && serverAliveIntervalSeconds == other.serverAliveIntervalSeconds
                && serverAliveCountMax == other.serverAliveCountMax
                && Objects.equals(id, other.id)
                && Objects.equals(name, other.name)
                && Objects.equals(host, other.host)
                && Objects.equals(username, other.username)
                && authMethod == other.authMethod
                && Objects.equals(password, other.password)
                && keySource == other.keySource
                && Objects.equals(privateKeyPath, other.privateKeyPath)
                && Objects.equals(privateKeyPem, other.privateKeyPem)
                && Objects.equals(privateKeyPassphrase, other.privateKeyPassphrase)
                && Objects.equals(acceptedHostKey, other.acceptedHostKey)
                && Objects.equals(acceptedHostKeyType, other.acceptedHostKeyType)
                && Objects.equals(forwards, other.forwards);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, host, port, username);
    }

    @Override
    public String toString() {
        return "SshTunnel[" + name + ", " + getEndpointDescription() + ", " + forwards.size() + " forward(s)]";
    }
}
