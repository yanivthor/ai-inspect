package com.inspect.policy;

import com.inspect.model.Finding;
import com.inspect.model.Severity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Replaces every HIGH-severity span with {@code [DETECTOR_ID]}, merging overlaps so two
 * detectors claiming the same characters produce one marker, not a mangled double replacement.
 * Only HIGH: a redaction is a lossy edit to someone's text, and MEDIUM findings (a block of
 * code, a possible steering attempt) are things to warn about, not to cut out silently.
 */
public final class Redactor {
    private Redactor() {}

    public static String redact(String text, List<Finding> findings) {
        List<Finding> spans = new ArrayList<>(findings.stream()
                .filter(f -> f.severity() == Severity.HIGH)
                .sorted(Comparator.comparingInt(Finding::start))
                .toList());
        if (spans.isEmpty()) return text;

        StringBuilder out = new StringBuilder(text.length());
        int cursor = 0;
        int i = 0;
        while (i < spans.size()) {
            int start = spans.get(i).start();
            int end = spans.get(i).end();
            List<String> ids = new ArrayList<>(List.of(spans.get(i).detector()));
            int j = i + 1;
            while (j < spans.size() && spans.get(j).start() < end) {
                end = Math.max(end, spans.get(j).end());
                if (!ids.contains(spans.get(j).detector())) ids.add(spans.get(j).detector());
                j++;
            }
            out.append(text, cursor, start).append('[').append(String.join("+", ids)).append(']');
            cursor = end;
            i = j;
        }
        out.append(text, cursor, text.length());
        return out.toString();
    }
}
