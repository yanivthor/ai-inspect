package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** International bank account numbers: country code, two check digits, up to 30 alphanumerics, mod-97 valid. */
@Component
public class IbanDetector implements Detector {

    public static final String ID = "IBAN";

    private static final Pattern CANDIDATE =
            Pattern.compile("(?<![A-Z0-9])[A-Z]{2}\\d{2}(?:\\s?[A-Z0-9]{4}){2,7}(?:\\s?[A-Z0-9]{1,4})?(?![A-Z0-9])");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> detect(Interaction interaction) {
        List<Finding> findings = new ArrayList<>();
        Matcher m = CANDIDATE.matcher(interaction.text());
        while (m.find()) {
            String compact = m.group().replaceAll("\\s", "");
            if (!Iban.isValid(compact)) continue;
            findings.add(Finding.certain(ID, Severity.HIGH, m.start(), m.end(),
                    Spans.mask(compact, 4, 4),
                    "Passes the ISO 13616 mod-97 check that every IBAN satisfies."));
        }
        return findings;
    }
}
