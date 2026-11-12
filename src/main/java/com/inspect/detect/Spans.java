package com.inspect.detect;

/** Small helpers shared by detectors for building safe evidence strings. */
final class Spans {
    private Spans() {}

    /** Keeps the first {@code head} and last {@code tail} characters, masks the rest. */
    static String mask(String raw, int head, int tail) {
        if (raw.length() <= head + tail) return "*".repeat(raw.length());
        return raw.substring(0, head) + "*".repeat(raw.length() - head - tail)
                + raw.substring(raw.length() - tail);
    }

    static String digitsOnly(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') b.append(c);
        }
        return b.toString();
    }
}
