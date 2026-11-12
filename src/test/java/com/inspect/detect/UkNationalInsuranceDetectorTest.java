package com.inspect.detect;

import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class UkNationalInsuranceDetectorTest {

    private final UkNationalInsuranceDetector detector = new UkNationalInsuranceDetector();

    @Test
    void spacedFormatIsFound() {
        var f = detector.detect(prompt("Her NI number is JG 10 32 45 B, please update payroll."));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(f.get(0).evidence()).doesNotContain("JG103245B");
    }

    @Test
    void compactFormatIsFound() {
        assertThat(detector.detect(prompt("NI: AB123456A"))).hasSize(1);
    }

    /**
     * HMRC's own documentation example QQ123456C is deliberately NOT matched: Q is never an issued
     * first letter, and the detector encodes that. It is a placeholder, like AKIA...EXAMPLE.
     */
    @Test
    void hmrcDocumentationExampleIsNotFound() {
        assertThat(detector.detect(prompt("For example QQ 12 34 56 C"))).isEmpty();
    }

    @Test
    void unissuedPrefixIsNotFound() {
        assertThat(detector.detect(prompt("Ref BG123456A"))).isEmpty();
    }

    @Test
    void disallowedFirstLetterIsNotFound() {
        assertThat(detector.detect(prompt("Ref DA123456A"))).isEmpty();
    }

    @Test
    void disallowedSuffixIsNotFound() {
        assertThat(detector.detect(prompt("Ref AB123456E"))).isEmpty();
    }
}
