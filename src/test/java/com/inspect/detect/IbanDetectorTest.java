package com.inspect.detect;

import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class IbanDetectorTest {

    private final IbanDetector detector = new IbanDetector();

    @Test
    void ukIbanIsFound() {
        var f = detector.detect(prompt("Please pay into GB82 WEST 1234 5698 7654 32 by Friday."));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(f.get(0).evidence()).doesNotContain("GB82WEST12345698765432");
    }

    @Test
    void germanIbanIsFound() {
        assertThat(detector.detect(prompt("IBAN: DE89 3704 0044 0532 0130 00"))).hasSize(1);
    }

    @Test
    void badChecksumIsNotFound() {
        assertThat(detector.detect(prompt("Pay GB82 WEST 1234 5698 7654 33"))).isEmpty();
    }

    @Test
    void ibanShapedGarbageIsNotFound() {
        assertThat(detector.detect(prompt("Part number AB12XXXXYYYYZZZZ1234 is back-ordered"))).isEmpty();
    }
}
