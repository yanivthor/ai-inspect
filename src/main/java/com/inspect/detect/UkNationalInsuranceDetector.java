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
 * UK National Insurance numbers, per HMRC's published format: two letters, six digits, a final
 * letter A-D. The first letter is never D, F, I, Q, U or V; the second is additionally never O;
 * and seven prefixes are reserved and never issued. Encoding those exclusions is what separates
 * an NI number from the many two-letters-six-digits product codes that otherwise look the same.
 */
@Component
public class UkNationalInsuranceDetector implements Detector {

    public static final String ID = "UK_NI_NUMBER";

    private static final Pattern CANDIDATE = Pattern.compile(
            "(?<![A-Za-z0-9])([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z])\\s?(\\d{2})\\s?(\\d{2})\\s?(\\d{2})\\s?([A-D])(?![A-Za-z0-9])",
            Pattern.CASE_INSENSITIVE);

    private static final Set<String> UNISSUED_PREFIXES = Set.of("BG", "GB", "NK", "KN", "TN", "NT", "ZZ");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        List<Finding> findings = new ArrayList<>();
        Matcher m = CANDIDATE.matcher(interaction.text());
        while (m.find()) {
            String prefix = m.group(1).toUpperCase();
            if (UNISSUED_PREFIXES.contains(prefix)) continue;
            String compact = m.group().replaceAll("\\s", "").toUpperCase();
            findings.add(Finding.certain(ID, Severity.HIGH, m.start(), m.end(),
                    Spans.mask(compact, 2, 1),
                    "Matches the HMRC National Insurance number format, including its prefix exclusions."));
        }
        return findings;
    }
}
