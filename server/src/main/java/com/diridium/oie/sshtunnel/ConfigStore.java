/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

/**
 * Persistence and encryption seam. Production uses {@link EngineConfigStore}
 * (ConfigurationController-backed); tests use an in-memory fake so no engine
 * singletons are needed.
 */
public interface ConfigStore {

    String getProperty(String name);

    void saveProperty(String name, String value);

    String encrypt(String value);

    String decrypt(String value);
}
