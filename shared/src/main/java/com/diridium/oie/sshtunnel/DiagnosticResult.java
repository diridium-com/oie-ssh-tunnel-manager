/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Result of a staged connection diagnostic: an ordered list of steps plus an
 * overall verdict. Overall success means no step failed (warnings are allowed).
 */
public class DiagnosticResult implements Serializable {

    private boolean success;
    private String summary = "";
    private List<DiagnosticStep> steps = new ArrayList<>();

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<DiagnosticStep> getSteps() {
        return steps;
    }

    public void setSteps(List<DiagnosticStep> steps) {
        this.steps = steps != null ? steps : new ArrayList<>();
    }

    /** Adds a step and returns its status, for convenient inline use. */
    public StepStatus add(String name, StepStatus status, String detail, long durationMs) {
        steps.add(new DiagnosticStep(name, status, detail, durationMs));
        return status;
    }

    /** Adds a step carrying an actionable hint. */
    public StepStatus add(String name, StepStatus status, String detail, long durationMs, String hint) {
        steps.add(new DiagnosticStep(name, status, detail, durationMs, hint));
        return status;
    }

    /** Recomputes success (no FAIL step) and a one-line summary. */
    public void finish() {
        long fails = steps.stream().filter(s -> s.getStatus() == StepStatus.FAIL).count();
        long warns = steps.stream().filter(s -> s.getStatus() == StepStatus.WARN).count();
        success = fails == 0;
        if (success) {
            summary = "All checks passed" + (warns > 0 ? " (" + warns + " warning(s))" : "") + ".";
        } else {
            var firstFail = steps.stream()
                    .filter(s -> s.getStatus() == StepStatus.FAIL)
                    .findFirst()
                    .orElse(null);
            summary = "Failed at: " + (firstFail != null ? firstFail.getName() : "unknown")
                    + (firstFail != null && !firstFail.getDetail().isEmpty() ? " - " + firstFail.getDetail() : "");
        }
    }

    @Override
    public String toString() {
        return (success ? "OK" : "FAILED") + ": " + summary;
    }
}
