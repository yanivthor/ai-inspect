package com.inspect.detect;

import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class EmailDetectorTest {

    private final EmailDetector detector = new EmailDetector();

    @Test
    void realLookingAddressIsLow() {
        var f = detector.detect(prompt("Forward this to dave@acme.co.uk please"));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.LOW);
        assertThat(f.get(0).evidence()).doesNotContain("dave@");
    }

    @Test
    void multipleAddressesAreEachFound() {
        assertThat(detector.detect(prompt("cc: ann@acme.io, bob@corp.com"))).hasSize(2);
    }

    @Test
    void reservedDocumentationDomainIsNotFound() {
        assertThat(detector.detect(prompt("Write to nobody@example.com"))).isEmpty();
    }

    @Test
    void reservedTldIsNotFound() {
        assertThat(detector.detect(prompt("Use x@foo.test in the fixture"))).isEmpty();
    }
}
