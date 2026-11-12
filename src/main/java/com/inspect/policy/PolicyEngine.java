package com.inspect.policy;

import com.inspect.config.InspectProperties;
import com.inspect.config.InspectProperties.DestinationKind;
import com.inspect.config.InspectProperties.PolicyRule;
import com.inspect.config.InspectProperties.When;
import com.inspect.detect.Detector;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Every rule is evaluated and the most severe matching action wins (ALLOW < NUDGE < REDACT <
 * BLOCK); on a tie the earlier rule in the list wins. Rule order therefore never lets a weak
 * rule shadow a strong one: a NUDGE listed first cannot let an unredacted card number through.
 * No findings or no match is ALLOW.
 * <p>
 * Refuses to start if a rule names a detector that does not exist. A typo in a rule would
 * otherwise produce a rule that never fires, which looks exactly like a rule that is working.
 */
@Component
public class PolicyEngine {

    private final List<PolicyRule> rules;
    private final Set<String> sanctioned;

    public PolicyEngine(InspectProperties properties, List<Detector> detectors) {
        Set<String> known = detectors.stream().map(Detector::id).collect(Collectors.toSet());
        for (PolicyRule rule : properties.policies()) {
            String id = rule.when().detector();
            if (id != null && !known.contains(id)) {
                throw new IllegalStateException("inspect.policies names unknown detector '" + id
                        + "'. Known: " + known.stream().sorted().collect(Collectors.joining(", ")));
            }
            When w = rule.when();
            if (id == null && w.severity() == null && w.minScore() == null) {
                throw new IllegalStateException("inspect.policies rule '" + rule.reason()
                        + "' has no finding-level condition (detector, severity or min-score); it would match any finding");
            }
            if (w.minScore() != null && (w.minScore() < 0 || w.minScore() > 1)) {
                throw new IllegalStateException("inspect.policies rule '" + rule.reason()
                        + "' has min-score " + w.minScore() + " outside 0..1");
            }
        }
        this.rules = List.copyOf(properties.policies());
        this.sanctioned = properties.sanctionedDestinations().stream()
                .map(d -> d.toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
    }

    public Optional<PolicyRule> decide(Interaction interaction, List<Finding> findings) {
        if (findings.isEmpty()) return Optional.empty();
        DestinationKind kind = sanctioned.contains(interaction.destination().toLowerCase(Locale.ROOT))
                ? DestinationKind.SANCTIONED : DestinationKind.UNSANCTIONED;
        PolicyRule best = null;
        for (PolicyRule rule : rules) {
            When when = rule.when();
            if (when.destination() != null && when.destination() != kind) continue;
            if (when.channel() != null && when.channel() != interaction.channel()) continue;
            if (when.direction() != null && when.direction() != interaction.direction()) continue;
            if (findings.stream().anyMatch(f -> matchesFinding(when, f))
                    && (best == null || rule.action().ordinal() > best.action().ordinal())) {
                best = rule;
            }
        }
        return Optional.ofNullable(best);
    }

    private static boolean matchesFinding(When when, Finding f) {
        if (when.detector() != null && !when.detector().equals(f.detector())) return false;
        if (when.severity() != null && f.severity().compareTo(when.severity()) < 0) return false;
        if (when.minScore() != null && f.score() < when.minScore()) return false;
        return true;
    }
}
