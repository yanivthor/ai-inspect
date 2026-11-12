package com.inspect.policy;

import com.inspect.model.Finding;
import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RedactorTest {

    private static Finding f(String det, Severity sev, int start, int end) {
        return Finding.certain(det, sev, start, end, "e", "x");
    }

    @Test
    void highSpanIsReplacedAndSurroundingTextPreserved() {
        String text = "Card 4539 1488 0343 6467 expires soon.";
        String out = Redactor.redact(text, List.of(f("ID", Severity.HIGH, 5, 24)));
        assertThat(out).isEqualTo("Card [ID] expires soon.");
    }

    @Test
    void overlappingSpansMergeIntoOneMarker() {
        String text = "0123456789";
        String out = Redactor.redact(text, List.of(f("A", Severity.HIGH, 2, 6), f("B", Severity.HIGH, 4, 8)));
        assertThat(out).isEqualTo("01[A+B]89");
    }

    @Test
    void separateSpansGetSeparateMarkers() {
        String out = Redactor.redact("aa bb cc", List.of(f("A", Severity.HIGH, 0, 2), f("B", Severity.HIGH, 6, 8)));
        assertThat(out).isEqualTo("[A] bb [B]");
    }

    @Test
    void mediumAndLowSpansAreUntouched() {
        String text = "keep this and that";
        String out = Redactor.redact(text, List.of(f("M", Severity.MEDIUM, 0, 4), f("L", Severity.LOW, 10, 14)));
        assertThat(out).isEqualTo(text);
    }

    @Test
    void unsortedInputIsHandled() {
        String out = Redactor.redact("aa bb cc", List.of(f("B", Severity.HIGH, 6, 8), f("A", Severity.HIGH, 0, 2)));
        assertThat(out).isEqualTo("[A] bb [B]");
    }
}
