package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class CreditCardDetectorTest {

    private final CreditCardDetector detector = new CreditCardDetector();

    @Test
    void luhnValidNumberWithSpacesIsHigh() {
        List<Finding> f = detector.detect(prompt("My card is 4539 1488 0343 6467, expiry 04/28."));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(f.get(0).detector()).isEqualTo("CREDIT_CARD");
    }

    @Test
    void dashSeparatedNumberIsFound() {
        assertThat(detector.detect(prompt("Card: 5425-2334-3010-9903"))).hasSize(1);
    }

    @Test
    void luhnFailureIsNotFound() {
        assertThat(detector.detect(prompt("My card is 4539 1488 0343 6466"))).isEmpty();
    }

    @Test
    void repeatedDigitsAreNotFound() {
        assertThat(detector.detect(prompt("Placeholder 0000 0000 0000 0000 in the form"))).isEmpty();
    }

    @Test
    void wellKnownTestNumberIsLow() {
        List<Finding> f = detector.detect(prompt("Use 4242 4242 4242 4242 in the sandbox"));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.LOW);
    }

    @Test
    void phoneNumberIsNotFound() {
        assertThat(detector.detect(prompt("Call me on 0207 946 0958 after lunch"))).isEmpty();
    }

    @Test
    void evidenceMasksTheMiddleDigits() {
        Finding f = detector.detect(prompt("Card 4539148803436467 please")).get(0);
        assertThat(f.evidence()).doesNotContain("4539148803436467").startsWith("4539").endsWith("6467");
        assertThat(f.evidence()).contains("********");
    }
}
