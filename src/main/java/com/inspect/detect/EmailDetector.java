package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Email addresses, at LOW severity: an address on its own is rarely the problem, but a list of
 * them is, and the finding gives the policy layer something to count. Reserved documentation
 * domains (RFC 2606 / 6761) are skipped outright - they are placeholders by definition, and
 * reporting them is the single biggest source of false positives in naive DLP.
 */
@Component
public class EmailDetector implements Detector {

    public static final String ID = "EMAIL";

    private static final Pattern CANDIDATE = Pattern.compile(
            "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}(?![A-Za-z0-9.-])");

    private static final Set<String> PLACEHOLDER_DOMAINS = Set.of(
            "example.com", "example.org", "example.net");
    private static final Set<String> PLACEHOLDER_TLDS = Set.of("example", "test", "invalid", "localhost");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        List<Finding> findings = new ArrayList<>();
        Matcher m = CANDIDATE.matcher(interaction.text());
        while (m.find()) {
            String address = m.group();
            String domain = address.substring(address.indexOf('@') + 1).toLowerCase();
            String tld = domain.substring(domain.lastIndexOf('.') + 1);
            if (PLACEHOLDER_DOMAINS.contains(domain) || PLACEHOLDER_TLDS.contains(tld)) continue;
            String local = address.substring(0, address.indexOf('@'));
            findings.add(Finding.certain(ID, Severity.LOW, m.start(), m.end(),
                    Spans.mask(local, 1, 0) + "@" + domain,
                    "An email address on a non-placeholder domain."));
        }
        return findings;
    }
}
