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
 * Payment card numbers: 13-19 digits, optionally separated by spaces or dashes, Luhn-valid.
 * <p>
 * Two deliberate precision choices. A run of one repeated digit is Luhn-valid (0000 0000 0000 0000
 * sums to zero) and is never a card, so it is excluded. And the handful of test numbers every
 * payment provider publishes are reported at LOW severity rather than suppressed: they are not
 * sensitive, but a user pasting one is usually about to paste a real one, and the nudge is cheap.
 */
@Component
public class CreditCardDetector implements Detector {

    public static final String ID = "CREDIT_CARD";

    private static final Pattern CANDIDATE =
            Pattern.compile("(?<![\\d-])(?:\\d[ -]?){12,18}\\d(?![\\d-])");

    private static final Set<String> WELL_KNOWN_TEST_NUMBERS = Set.of(
            "4111111111111111", "4242424242424242", "4000000000000002",
            "5555555555554444", "5105105105105100", "378282246310005",
            "371449635398431", "6011111111111117", "3530111333300000");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        List<Finding> findings = new ArrayList<>();
        Matcher m = CANDIDATE.matcher(interaction.text());
        while (m.find()) {
            String digits = Spans.digitsOnly(m.group());
            if (digits.length() < 13 || digits.length() > 19) continue;
            if (!Luhn.isValid(digits)) continue;
            if (digits.chars().distinct().count() == 1) continue;

            String evidence = Spans.mask(digits, 4, 4);
            if (WELL_KNOWN_TEST_NUMBERS.contains(digits)) {
                findings.add(new Finding(ID, Severity.LOW, m.start(), m.end(), evidence,
                        "A published test card number, not a real one - but the next paste often is.",
                        1.0));
            } else {
                findings.add(Finding.certain(ID, Severity.HIGH, m.start(), m.end(), evidence,
                        digits.length() + "-digit number passing the Luhn check used by every payment card."));
            }
        }
        return findings;
    }
}
