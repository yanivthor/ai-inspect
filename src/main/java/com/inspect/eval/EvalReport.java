package com.inspect.eval;

import com.inspect.model.Direction;

import java.time.Instant;
import java.util.List;

/**
 * The eval corpus run against the live detectors. Served by {@code GET /api/eval} and asserted
 * on by {@code EvalHarnessTest}, so the number on the dashboard and the number that gates the
 * build come from the same code.
 */
public record EvalReport(
        Instant generatedAt,
        int samples,
        List<DetectorMetrics> detectors,
        DetectorMetrics total,
        List<SampleResult> results
) {
    public record DetectorMetrics(String detector, int tp, int fp, int fn, int tn,
                                  double precision, double recall, double f1) {
        static DetectorMetrics of(String detector, int tp, int fp, int fn, int tn) {
            double p = tp + fp == 0 ? 1.0 : (double) tp / (tp + fp);
            double r = tp + fn == 0 ? 1.0 : (double) tp / (tp + fn);
            double f1 = p + r == 0 ? 0 : 2 * p * r / (p + r);
            return new DetectorMetrics(detector, tp, fp, fn, tn, p, r, f1);
        }
    }

    /** One corpus sample and what happened. {@code outcome} is PASS, FALSE_POSITIVE, FALSE_NEGATIVE or BOTH. */
    public record SampleResult(String id, Direction direction, String text,
                               List<String> expected, List<String> actual,
                               List<String> falsePositives, List<String> falseNegatives,
                               String outcome) {
    }
}
