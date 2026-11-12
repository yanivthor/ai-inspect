package com.inspect.service;

import com.inspect.config.InspectProperties.PolicyRule;
import com.inspect.detect.Detector;
import com.inspect.model.Action;
import com.inspect.model.Decision;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.policy.PolicyEngine;
import com.inspect.policy.Redactor;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Runs every detector, asks the policy what to do, redacts if told to, publishes the decision.
 * <p>
 * Two things it is careful about. A detector that throws is isolated and counted, not allowed
 * to fail the request: one bad regex must not turn the whole inspection off, and the metric is
 * what makes that failure visible rather than silent. And the timer wraps the whole thing,
 * detectors and policy together, because the latency a user feels is the sum.
 */
@Service
public class InspectionService {

    private static final Logger log = LoggerFactory.getLogger(InspectionService.class);

    private final List<Detector> detectors;
    private final PolicyEngine policy;
    private final ApplicationEventPublisher events;
    private final MeterRegistry registry;
    private final Timer latency;

    public InspectionService(List<Detector> detectors, PolicyEngine policy,
                             ApplicationEventPublisher events, MeterRegistry registry) {
        this.detectors = List.copyOf(detectors);
        this.policy = policy;
        this.events = events;
        this.registry = registry;
        this.latency = Timer.builder("inspect.latency")
                .description("Wall-clock time to inspect one interaction, detectors and policy included")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);
        log.info("Inspection service ready with {} detectors: {}", detectors.size(),
                detectors.stream().map(Detector::id).sorted().toList());
    }

    public List<String> detectorIds() {
        return detectors.stream().map(Detector::id).sorted().toList();
    }

    public Decision inspect(Interaction interaction) {
        long started = System.nanoTime();

        List<Finding> findings = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        for (Detector detector : detectors) {
            try {
                List<Finding> found = detector.detect(interaction);
                findings.addAll(found);
                if (!found.isEmpty()) {
                    Counter.builder("inspect.findings").tag("detector", detector.id())
                            .register(registry).increment(found.size());
                }
            } catch (RuntimeException e) {
                log.error("Detector {} failed; continuing without it", detector.id(), e);
                failed.add(detector.id());
                Counter.builder("inspect.detector.errors").tag("detector", detector.id())
                        .register(registry).increment();
            }
        }
        findings.sort(Comparator.comparingInt(Finding::start));

        Optional<PolicyRule> matched = policy.decide(interaction, findings);
        Action action = matched.map(PolicyRule::action).orElse(Action.ALLOW);
        String explanation = matched.map(PolicyRule::reason).orElse(
                findings.isEmpty() ? (failed.isEmpty() ? "Nothing sensitive found."
                        : "Nothing found, but detectors failed: " + String.join(", ", failed) + ".") : "Findings below the policy threshold.");
        String redacted = action == Action.REDACT ? Redactor.redact(interaction.text(), findings) : null;

        long elapsedNanos = System.nanoTime() - started;
        latency.record(elapsedNanos, TimeUnit.NANOSECONDS);
        Counter.builder("inspect.decisions").tag("action", action.name()).register(registry).increment();

        Decision decision = new Decision(interaction.interactionId(), action, List.copyOf(findings),
                redacted, explanation, elapsedNanos / 1_000_000, List.copyOf(failed));
        events.publishEvent(new InspectionDecided(interaction, decision));
        return decision;
    }
}
