package com.inspect.service;

import com.inspect.config.InspectProperties;
import com.inspect.config.InspectProperties.PolicyRule;
import com.inspect.config.InspectProperties.When;
import com.inspect.config.InspectProperties.Webhook;
import com.inspect.config.InspectProperties.DestinationKind;
import com.inspect.detect.*;
import com.inspect.model.Action;
import com.inspect.model.Severity;
import com.inspect.policy.PolicyEngine;
import io.micrometer.core.instrument.MeterRegistry;

import java.util.List;

/** Builds a hand-wired service with the same policy shape as application.yml. */
public final class TestServices {
    private TestServices() {}

    public static List<Detector> detectors() {
        return List.of(new CreditCardDetector(), new UkNationalInsuranceDetector(), new IbanDetector(),
                new EmailDetector(), new SecretDetector(), new PromptInjectionDetector(), new SourceCodeDetector());
    }

    public static InspectionService service(MeterRegistry registry) {
        List<Detector> detectors = detectors();
        var props = new InspectProperties(
                List.of("chat.openai.com", "claude.ai", "copilot.microsoft.com"),
                List.of(
                        new PolicyRule(Action.BLOCK, "secret", new When("SECRET", null, null, null, null, null)),
                        new PolicyRule(Action.BLOCK, "injection", new When("PROMPT_INJECTION", null, null, null, null, 0.7)),
                        new PolicyRule(Action.NUDGE, "steer", new When("PROMPT_INJECTION", null, null, null, null, 0.4)),
                        new PolicyRule(Action.BLOCK, "unsanctioned", new When(null, Severity.HIGH, DestinationKind.UNSANCTIONED, null, null, null)),
                        new PolicyRule(Action.REDACT, "redact", new When(null, Severity.HIGH, null, null, null, null)),
                        new PolicyRule(Action.NUDGE, "internal", new When(null, Severity.MEDIUM, null, null, null, null))),
                new Webhook("", 1));
        return new InspectionService(detectors, new PolicyEngine(props, detectors), event -> {}, registry);
    }
}
