/* SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 Diridium Technologies Inc. */

package com.diridium.oie.sshtunnel;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DiagnosticResultTest {

    @Test
    void allPassIsSuccess() {
        var result = new DiagnosticResult();
        result.add("DNS", StepStatus.PASS, "ok", 1);
        result.add("Auth", StepStatus.PASS, "ok", 2);
        result.finish();

        assertTrue(result.isSuccess());
        assertTrue(result.getSummary().startsWith("All checks passed"));
    }

    @Test
    void warningStillSucceedsButIsNoted() {
        var result = new DiagnosticResult();
        result.add("Host key", StepStatus.WARN, "verification disabled", 1);
        result.finish();

        assertTrue(result.isSuccess());
        assertTrue(result.getSummary().contains("warning"));
    }

    @Test
    void anyFailIsFailureAndSummaryNamesFirstFailedStep() {
        var result = new DiagnosticResult();
        result.add("DNS", StepStatus.PASS, "ok", 1);
        result.add("TCP connection", StepStatus.FAIL, "connection refused", 2);
        result.add("Authentication", StepStatus.SKIP, "not reached", 0);
        result.finish();

        assertFalse(result.isSuccess());
        assertTrue(result.getSummary().contains("TCP connection"));
        assertTrue(result.getSummary().contains("connection refused"));
    }
}
