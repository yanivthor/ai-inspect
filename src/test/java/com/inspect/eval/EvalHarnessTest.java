package com.inspect.eval;

import com.inspect.model.Channel;
import com.inspect.model.Direction;
import com.inspect.model.Interaction;
import com.inspect.service.InspectionService;
import com.inspect.service.TestServices;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs a labelled corpus through the real detectors and policy, and reports precision/recall/F1 per detector. */
class EvalHarnessTest {

    private static final class Counts {
        int tp, fp, fn;
        double precision() { return tp + fp == 0 ? 1.0 : (double) tp / (tp + fp); }
        double recall() { return tp + fn == 0 ? 1.0 : (double) tp / (tp + fn); }
        double f1() { double p = precision(), r = recall(); return p + r == 0 ? 0 : 2 * p * r / (p + r); }
    }

    @Test
    void precisionAndRecallMeetTheBar() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        InspectionService service = TestServices.service(new SimpleMeterRegistry());

        Map<String, Counts> byDetector = new LinkedHashMap<>();
        for (String id : service.detectorIds()) byDetector.put(id, new Counts());

        List<String> misses = new ArrayList<>();
        int samples = 0;
        try (var reader = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("/corpus.jsonl"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                JsonNode n = mapper.readTree(line);
                samples++;
                Direction dir = n.has("direction") ? Direction.valueOf(n.get("direction").asString()) : Direction.PROMPT;
                Set<String> expected = new TreeSet<>();
                n.get("expected").forEach(e -> expected.add(e.asString()));
                var decision = service.inspect(new Interaction(n.get("id").asString(), "eval", "claude.ai",
                        Channel.BROWSER, dir, n.get("text").asString()));
                Set<String> fired = new TreeSet<>();
                decision.findings().forEach(f -> fired.add(f.detector()));

                for (var e : byDetector.entrySet()) {
                    boolean exp = expected.contains(e.getKey()), got = fired.contains(e.getKey());
                    Counts c = e.getValue();
                    if (exp && got) c.tp++;
                    else if (!exp && got) { c.fp++; misses.add("FP " + e.getKey() + " on " + n.get("id").asString()); }
                    else if (exp) { c.fn++; misses.add("FN " + e.getKey() + " on " + n.get("id").asString()); }
                }
            }
        }

        Counts total = new Counts();
        StringBuilder t = new StringBuilder();
        t.append(String.format("%nEVAL: %d samples%n", samples));
        t.append(String.format("%-18s %4s %4s %4s %9s %7s %6s%n", "detector", "TP", "FP", "FN", "precision", "recall", "F1"));
        t.append("-".repeat(58)).append('\n');
        for (var e : byDetector.entrySet()) {
            Counts c = e.getValue();
            total.tp += c.tp; total.fp += c.fp; total.fn += c.fn;
            t.append(String.format("%-18s %4d %4d %4d %9.3f %7.3f %6.3f%n", e.getKey(), c.tp, c.fp, c.fn, c.precision(), c.recall(), c.f1()));
        }
        t.append("-".repeat(58)).append('\n');
        t.append(String.format("%-18s %4d %4d %4d %9.3f %7.3f %6.3f%n", "MICRO TOTAL", total.tp, total.fp, total.fn, total.precision(), total.recall(), total.f1()));
        System.out.println(t);
        if (!misses.isEmpty()) System.out.println("Misses: " + misses);

        for (var e : byDetector.entrySet()) {
            assertThat(e.getValue().precision()).as("precision of %s (misses %s)", e.getKey(), misses).isGreaterThanOrEqualTo(0.9);
            assertThat(e.getValue().recall()).as("recall of %s (misses %s)", e.getKey(), misses).isGreaterThanOrEqualTo(0.8);
        }
    }
}
