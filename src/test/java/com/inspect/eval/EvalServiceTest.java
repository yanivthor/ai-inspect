package com.inspect.eval;

import com.inspect.service.TestServices;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EvalServiceTest {

    @Test
    void latencyPercentilesAreOrderedAndCoverEveryDetector() {
        var detectors = TestServices.detectors();
        var report = new EvalService(detectors, TestServices.policyEngine()).latency(50);
        assertThat(report.p50Ms()).isLessThanOrEqualTo(report.p95Ms());
        assertThat(report.p95Ms()).isLessThanOrEqualTo(report.p99Ms());
        assertThat(report.p99Ms()).isLessThanOrEqualTo(report.maxMs());
        assertThat(report.perDetectorMs()).hasSize(detectors.size());
    }
}
