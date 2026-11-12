package com.inspect.eval;

import com.inspect.eval.EvalReport.DetectorMetrics;
import com.inspect.service.TestServices;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The build gate. Uses {@link EvalService}, the same code behind the /api/eval dashboard, so the
 * number that fails the build is the number people see.
 */
class EvalHarnessTest {

    @Test
    void precisionAndRecallMeetTheBar() {
        EvalReport report = new EvalService(TestServices.detectors(), TestServices.policyEngine()).run();

        List<String> misses = new ArrayList<>();
        report.results().forEach(r -> {
            r.falsePositives().forEach(d -> misses.add("FP " + d + " on " + r.id()));
            r.falseNegatives().forEach(d -> misses.add("FN " + d + " on " + r.id()));
        });

        StringBuilder t = new StringBuilder();
        t.append(String.format("%nEVAL: %d samples%n", report.samples()));
        t.append(String.format("%-18s %4s %4s %4s %9s %7s %6s%n", "detector", "TP", "FP", "FN", "precision", "recall", "F1"));
        t.append("-".repeat(58)).append('\n');
        for (DetectorMetrics m : report.detectors()) row(t, m.detector(), m);
        t.append("-".repeat(58)).append('\n');
        row(t, "MICRO TOTAL", report.total());
        System.out.println(t);
        if (!misses.isEmpty()) System.out.println("Misses: " + misses);

        for (DetectorMetrics m : report.detectors()) {
            assertThat(m.precision()).as("precision of %s (misses %s)", m.detector(), misses).isGreaterThanOrEqualTo(0.9);
            assertThat(m.recall()).as("recall of %s (misses %s)", m.detector(), misses).isGreaterThanOrEqualTo(0.8);
        }
    }

    private static void row(StringBuilder t, String name, DetectorMetrics m) {
        t.append(String.format("%-18s %4d %4d %4d %9.3f %7.3f %6.3f%n", name, m.tp(), m.fp(), m.fn(), m.precision(), m.recall(), m.f1()));
    }
}
