package com.inspect.detect;

import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class SourceCodeDetectorTest {

    private final SourceCodeDetector detector = new SourceCodeDetector();

    @Test
    void javaClassIsMedium() {
        var f = detector.detect(prompt("""
                public class Account {
                    private final String id;
                    public Account(String id) { this.id = id; }
                    public String id() { return id; }
                }
                """));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void pythonFunctionIsFound() {
        assertThat(detector.detect(prompt("""
                import os
                def load(path):
                    if not os.path.exists(path):
                        return None
                    return open(path).read()
                """))).hasSize(1);
    }

    @Test
    void proseIsNotFound() {
        assertThat(detector.detect(prompt("""
                Thanks for getting back to me about the renewal.
                I will check with finance and let you know on Monday
                whether we can move forward with the new terms
                """))).isEmpty();
    }

    @Test
    void singleCodeLikeLineIsNotFound() {
        assertThat(detector.detect(prompt("x = 1;"))).isEmpty();
    }
}
