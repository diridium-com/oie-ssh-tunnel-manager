/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;

/** A host key fetched from an SSH server, for display and explicit acceptance in the UI. */
public class HostKeyInfo implements Serializable {

    /** Key algorithm, e.g. ssh-ed25519 or ecdsa-sha2-nistp256. */
    private String keyType = "";
    /** OpenSSH-style fingerprint, e.g. SHA256:xxxx. */
    private String fingerprint = "";
    /** Base64 wire-format public key blob, stored on acceptance. */
    private String publicKey = "";

    public HostKeyInfo() {
    }

    public HostKeyInfo(String keyType, String fingerprint, String publicKey) {
        this.keyType = keyType;
        this.fingerprint = fingerprint;
        this.publicKey = publicKey;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        return keyType + " " + fingerprint;
    }
}
