package com.inspect.detect;

import java.util.HashMap;
import java.util.Map;

/**
 * Shannon entropy in bits per character. Random keys sit above ~3.5; words, placeholders and
 * repeated characters sit well below. It is the one signal that separates {@code sk_live_9f3K...}
 * from {@code sk_live_your_key_here} when both match the same pattern.
 */
final class Entropy {
    private Entropy() {}

    static double bitsPerChar(String s) {
        if (s.isEmpty()) return 0;
        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < s.length(); i++) counts.merge(s.charAt(i), 1, Integer::sum);
        double h = 0;
        for (int c : counts.values()) {
            double p = (double) c / s.length();
            h -= p * (Math.log(p) / Math.log(2));
        }
        return h;
    }
}
