package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class SecretDetectorTest {

    private final SecretDetector detector = new SecretDetector();

    private void assertNoLeak(List<Finding> findings, String secret) {
        assertThat(findings).isNotEmpty();
        for (Finding f : findings) assertThat(f.evidence()).doesNotContain(secret);
    }

    @Test
    void awsDocumentedExampleKeyIsNotFound() {
        assertThat(detector.detect(prompt("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))).isEmpty();
    }

    @Test
    void realisticAwsKeyIsHigh() {
        String key = "AKIAJ3K9QZ7MXP2LW5TD";
        var f = detector.detect(prompt("Here is the key: " + key));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
        assertNoLeak(f, key);
    }

    @Test
    void stripeTestKeyIsLow() {
        String key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
        var f = detector.detect(prompt("key " + key));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.LOW);
        assertNoLeak(f, key);
    }

    @Test
    void stripeLiveKeyIsHigh() {
        String key = "sk_live_51HqLyjWDarjtT1zdp7dcAb9X";
        var f = detector.detect(prompt("key " + key));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
        assertNoLeak(f, key);
    }

    @Test
    void placeholderApiKeyIsNotFound() {
        assertThat(detector.detect(prompt("api_key = your_api_key_here"))).isEmpty();
    }

    @Test
    void changemePasswordIsNotFound() {
        assertThat(detector.detect(prompt("password: changeme"))).isEmpty();
    }

    @Test
    void highEntropyAssignmentIsHigh() {
        String value = "9fK3mQz8vL2pX7nR4tW1yB6cD0eH5gJ";
        var f = detector.detect(prompt("api_key: " + value));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
        assertNoLeak(f, value);
    }

    @Test
    void privateKeyHeaderIsFound() {
        var f = detector.detect(prompt("-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void jwtIsFound() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        var f = detector.detect(prompt("Authorization: Bearer " + jwt));
        assertThat(f).hasSize(1);
        assertNoLeak(f, jwt);
    }

    @Test
    void envStyleAndCamelCaseKeysAreFound() {
        for (String line : new String[]{
                "OPENAI_API_KEY=9fK3mQz8vL2pX7nR4tW1yB6cD0eH5gJ",
                "DB_PASSWORD=9fK3mQz8vL2pX7nR4tW1yB6cD0eH5gJ",
                "aws_secret_access_key=9fK3mQz8vL2pX7nR4tW1yB6cD0eH5gJ",
                "dbPassword: 9fK3mQz8vL2pX7nR4tW1yB6cD0eH5gJ"}) {
            assertThat(detector.detect(prompt(line))).as(line).hasSize(1);
        }
    }

    @Test
    void callsAndPathsAssignedToTokenAreNotSecrets() {
        assertThat(detector.detect(prompt("token = tokenizer.encode(text)"))).isEmpty();
        assertThat(detector.detect(prompt("token: /var/run/secrets/kubernetes.io/serviceaccount"))).isEmpty();
    }

    @Test
    void anthropicKeyYieldsExactlyOneFinding() {
        var f = detector.detect(prompt("key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));
        assertThat(f).hasSize(1);
        assertThat(f.get(0).evidence()).contains("Anthropic");
    }

    @Test
    void longIdentifierRunsDoNotBlowUp() {
        String hostile = "token" + "a.".repeat(50_000);
        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofMillis(500),
                () -> detector.detect(prompt(hostile)));
    }
}
