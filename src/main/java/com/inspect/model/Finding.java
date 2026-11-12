package com.inspect.model;

/**
 * One thing one detector found.
 *
 * @param detector    the detector's id, e.g. {@code CREDIT_CARD}
 * @param severity    how bad it would be for this to reach the destination
 * @param start       inclusive offset into the text
 * @param end         exclusive offset
 * @param evidence    a masked excerpt safe to show the user and to log
 * @param explanation why this matched, in words a user can disagree with
 * @param score       0..1 confidence; deterministic detectors use 1.0, heuristics report their score
 */
public record Finding(
        String detector,
        Severity severity,
        int start,
        int end,
        String evidence,
        String explanation,
        double score
) {
    public Finding {
        if (start < 0 || end < start) throw new IllegalArgumentException("bad span " + start + ".." + end);
        if (score < 0 || score > 1) throw new IllegalArgumentException("score out of range: " + score);
    }

    public static Finding certain(String detector, Severity severity, int start, int end,
                                  String evidence, String explanation) {
        return new Finding(detector, severity, start, end, evidence, explanation, 1.0);
    }
}
