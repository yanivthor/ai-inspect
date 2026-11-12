package com.inspect.eval;

import java.util.Map;

/**
 * A synthetic benchmark: {@code runs} inspections of a {@code textBytes}-byte prose document
 * carrying one email and one card number, timed individually. {@code perDetectorMs} is the mean
 * cost of each detector on its own, which is what tells you where the budget goes.
 */
public record LatencyReport(int runs, int textBytes, double p50Ms, double p95Ms, double p99Ms,
                            double maxMs, Map<String, Double> perDetectorMs) {
}
