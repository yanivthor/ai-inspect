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

    @Test
    void crlfDoesNotDriftTheStartOffset() {
        String prose = "Notes for the review\r\nplease read before Friday\r\nthanks all\r\n";
        String code = "public class A {\r\n    private int x;\r\n    public int x() { return x; }\r\n}\r\n";
        var f = detector.detect(prompt(prose + code));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).start()).isEqualTo(prose.length());
    }
}
