package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Credentials: provider-specific key formats, private key blocks, JWTs, and generic
 * {@code key = value} assignments whose value has the entropy of a real secret.
 * <p>
 * The problem is not finding strings that look like keys; it is <em>not</em> flagging the
 * placeholders that look exactly like them. Every provider publishes example keys in its docs
 * ({@code AKIAIOSFODNN7EXAMPLE}), every README says {@code API_KEY=your_key_here}, and a detector
 * that fires on those trains users to ignore it. So: known example keys are skipped, values that
 * read as placeholders are skipped, and a generic assignment only counts when its value is
 * high-entropy. Test-mode keys ({@code sk_test_...}) are reported at LOW, not suppressed - they
 * are harmless, but their presence is a strong hint the live one is nearby.
 */
@Component
public class SecretDetector implements Detector {

    public static final String ID = "SECRET";

    /** {@code hints}: case-sensitive literals, one of which the text must contain before the regex runs. */
    private record Rule(String name, Pattern pattern, Severity severity, String explanation, List<String> hints) {
        boolean mightMatch(String text) {
            for (String h : hints) if (text.contains(h)) return true;
            return false;
        }
    }

    private static final List<Rule> RULES = List.of(
            new Rule("AWS access key",
                    Pattern.compile("(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
                    Severity.HIGH, "Matches the AWS access key id format.", List.of("AKIA", "ASIA")),
            new Rule("GitHub token",
                    Pattern.compile("(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}(?![A-Za-z0-9])"),
                    Severity.HIGH, "Matches the GitHub personal/OAuth token format.", List.of("gh")),
            new Rule("Slack token",
                    Pattern.compile("(?<![A-Za-z0-9-])xox[bpoa]-[0-9A-Za-z-]{10,}(?![A-Za-z0-9-])"),
                    Severity.HIGH, "Matches the Slack API token format.", List.of("xox")),
            new Rule("Stripe live key",
                    Pattern.compile("(?<![A-Za-z0-9_])sk_live_[0-9A-Za-z]{16,}(?![A-Za-z0-9])"),
                    Severity.HIGH, "Matches the Stripe live secret key format.", List.of("sk_live_")),
            new Rule("Stripe test key",
                    Pattern.compile("(?<![A-Za-z0-9_])sk_test_[0-9A-Za-z]{16,}(?![A-Za-z0-9])"),
                    Severity.LOW, "A Stripe test-mode key. Harmless in itself, but the live one is usually nearby.", List.of("sk_test_")),
            new Rule("Anthropic API key",
                    Pattern.compile("(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
                    Severity.HIGH, "Matches the Anthropic API key format.", List.of("sk-ant-")),
            new Rule("OpenAI API key",
                    Pattern.compile("(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"),
                    Severity.HIGH, "Matches the OpenAI API key format.", List.of("sk-")),
            new Rule("private key block",
                    Pattern.compile("-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
                    Severity.HIGH, "A PEM private key header.", List.of("PRIVATE KEY")),
            new Rule("JWT",
                    Pattern.compile("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"),
                    Severity.HIGH, "A signed JSON Web Token.", List.of("eyJ"))
    );

    /** {@code api_key: value}, {@code password=value}, {@code "token": "value"} and friends. */
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)\\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret)\\b\"?\\s*[:=]\\s*[\"']?([^\\s\"',;]{8,})");

    private static final Pattern PLACEHOLDER = Pattern.compile(
            "(?i)^(?:<.*>|\\$\\{.*}|\\{\\{.*}}|x{4,}|\\*{4,}|\\.{3,}|.*(?:example|placeholder|your[_-]|changeme|redacted|dummy|sample|insert|replace|todo|fixme|password123|secret123).*)$");

    private static final double MIN_ENTROPY_BITS = 3.5;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        String text = interaction.text();
        List<Finding> findings = new ArrayList<>();

        for (Rule rule : RULES) {
            if (!rule.mightMatch(text)) continue;
            Matcher m = rule.pattern().matcher(text);
            while (m.find()) {
                String value = m.group();
                if (looksLikeExample(value)) continue;
                findings.add(Finding.certain(ID, rule.severity(), m.start(), m.end(),
                        rule.name() + " " + Spans.mask(value, 4, 2), rule.explanation()));
            }
        }

        if (!mightContainAssignment(text)) return findings;
        Matcher m = ASSIGNMENT.matcher(text);
        while (m.find()) {
            String value = m.group(2);
            if (overlapsAny(findings, m.start(2), m.end(2))) continue;
            if (PLACEHOLDER.matcher(value).matches() || looksLikeExample(value)) continue;
            double entropy = Entropy.bitsPerChar(value);
            if (entropy < MIN_ENTROPY_BITS) continue;
            findings.add(new Finding(ID, Severity.HIGH, m.start(2), m.end(2),
                    m.group(1).toLowerCase(Locale.ROOT) + " = " + Spans.mask(value, 3, 2),
                    String.format("Assigned to '%s' and has %.1f bits/char of entropy - the shape of a generated secret, not a word.",
                            m.group(1), entropy),
                    Math.min(1.0, 0.7 + (entropy - MIN_ENTROPY_BITS) * 0.3)));
        }
        return findings;
    }

    private static final List<String> ASSIGNMENT_HINTS =
            List.of("key", "secret", "token", "password", "passwd", "pwd");

    private static boolean mightContainAssignment(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        for (String h : ASSIGNMENT_HINTS) if (lower.contains(h)) return true;
        return false;
    }

    private static boolean looksLikeExample(String value) {
        String upper = value.toUpperCase(Locale.ROOT);
        return upper.contains("EXAMPLE") || upper.contains("XXXXXXXX") || upper.contains("PLACEHOLDER");
    }

    private static boolean overlapsAny(List<Finding> findings, int start, int end) {
        for (Finding f : findings) {
            if (start < f.end() && end > f.start()) return true;
        }
        return false;
    }
}
