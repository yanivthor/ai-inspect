package com.inspect.policy;

import com.inspect.config.InspectProperties;
import com.inspect.config.InspectProperties.DestinationKind;
import com.inspect.config.InspectProperties.PolicyRule;
import com.inspect.config.InspectProperties.When;
import com.inspect.config.InspectProperties.Webhook;
import com.inspect.detect.Detector;
import com.inspect.model.Action;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.inspect.Texts.of;
import static com.inspect.model.Direction.PROMPT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyEngineTest {

    private static Detector fake(String id) {
        return new Detector() {
            public String id() { return id; }
            public List<Finding> detect(Interaction i) { return List.of(); }
        };
    }

    private static PolicyRule rule(Action a, String reason, When w) {
        return new PolicyRule(a, reason, w);
    }

    private static When when(String detector, Severity sev, DestinationKind dest, Double minScore) {
        return new When(detector, sev, dest, null, null, minScore);
    }

    private static PolicyEngine engine(PolicyRule... rules) {
        var props = new InspectProperties(List.of("Claude.ai"), List.of(rules), new Webhook("", 1));
        return new PolicyEngine(props, List.of(fake("A"), fake("B")));
    }

    private static Finding finding(String det, Severity sev, double score) {
        return new Finding(det, sev, 0, 1, "e", "x", score);
    }

    private final Interaction toSanctioned = of(PROMPT, "claude.ai", "t");
    private final Interaction toUnsanctioned = of(PROMPT, "random.io", "t");

    @Test
    void firstMatchingRuleWins() {
        var e = engine(rule(Action.NUDGE, "first", when("A", null, null, null)),
                rule(Action.BLOCK, "second", when("A", null, null, null)));
        assertThat(e.decide(toSanctioned, List.of(finding("A", Severity.LOW, 1))))
                .get().extracting(PolicyRule::reason).isEqualTo("first");
    }

    @Test
    void ruleOrderDecidesNotSeverity() {
        var e = engine(rule(Action.NUDGE, "low", when("A", null, null, null)),
                rule(Action.BLOCK, "high", when("B", Severity.HIGH, null, null)));
        var found = e.decide(toSanctioned, List.of(finding("B", Severity.HIGH, 1), finding("A", Severity.LOW, 1)));
        assertThat(found).get().extracting(PolicyRule::reason).isEqualTo("low");
    }

    @Test
    void severityMeansAtLeast() {
        var e = engine(rule(Action.NUDGE, "medium+", when(null, Severity.MEDIUM, null, null)));
        assertThat(e.decide(toSanctioned, List.of(finding("A", Severity.LOW, 1)))).isEmpty();
        assertThat(e.decide(toSanctioned, List.of(finding("A", Severity.MEDIUM, 1)))).isPresent();
        assertThat(e.decide(toSanctioned, List.of(finding("A", Severity.HIGH, 1)))).isPresent();
    }

    @Test
    void unsanctionedDestinationMatchesOnlyNonSanctionedHostsCaseInsensitively() {
        var e = engine(rule(Action.BLOCK, "unsanctioned", when(null, null, DestinationKind.UNSANCTIONED, null)));
        var f = List.of(finding("A", Severity.HIGH, 1));
        assertThat(e.decide(toUnsanctioned, f)).isPresent();
        assertThat(e.decide(toSanctioned, f)).isEmpty();
        assertThat(e.decide(of(PROMPT, "CLAUDE.AI", "t"), f)).isEmpty();
    }

    @Test
    void sanctionedDestinationRuleMatchesSanctionedHost() {
        var e = engine(rule(Action.REDACT, "s", when(null, null, DestinationKind.SANCTIONED, null)));
        var f = List.of(finding("A", Severity.HIGH, 1));
        assertThat(e.decide(toSanctioned, f)).isPresent();
        assertThat(e.decide(toUnsanctioned, f)).isEmpty();
    }

    @Test
    void minScoreIsHonoured() {
        var e = engine(rule(Action.BLOCK, "scored", when("A", null, null, 0.7)));
        assertThat(e.decide(toSanctioned, List.of(finding("A", Severity.HIGH, 0.69)))).isEmpty();
        assertThat(e.decide(toSanctioned, List.of(finding("A", Severity.HIGH, 0.7)))).isPresent();
    }

    @Test
    void noFindingsIsEmpty() {
        var e = engine(rule(Action.BLOCK, "any", when(null, null, null, null)));
        assertThat(e.decide(toSanctioned, List.of())).isEmpty();
    }

    @Test
    void unknownDetectorIdFailsConstruction() {
        assertThatThrownBy(() -> engine(rule(Action.BLOCK, "typo", when("CREDIT_CRAD", null, null, null))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("CREDIT_CRAD");
    }
}
