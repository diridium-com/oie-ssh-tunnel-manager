/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;

/** One stage of a connection diagnostic: what was tried, how it went, and how long it took. */
public class DiagnosticStep implements Serializable {

    private String name = "";
    private StepStatus status = StepStatus.SKIP;
    private String detail = "";
    private long durationMs;

    public DiagnosticStep() {
    }

    public DiagnosticStep(String name, StepStatus status, String detail, long durationMs) {
        this.name = name;
        this.status = status;
        this.detail = detail;
        this.durationMs = durationMs;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public StepStatus getStatus() {
        return status;
    }

    public void setStatus(StepStatus status) {
        this.status = status;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public void setDurationMs(long durationMs) {
        this.durationMs = durationMs;
    }

    @Override
    public String toString() {
        return "[" + status + "] " + name + (detail.isEmpty() ? "" : " - " + detail);
    }
}
