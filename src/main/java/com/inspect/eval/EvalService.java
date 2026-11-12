package com.inspect.eval;

import com.inspect.detect.Detector;
import com.inspect.eval.EvalReport.DetectorMetrics;
import com.inspect.eval.EvalReport.SampleResult;
import com.inspect.model.Channel;
import com.inspect.model.Direction;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.policy.PolicyEngine;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

/**
 * Runs the labelled corpus ({@code eval/corpus.jsonl}) through the live detectors and scores
 * each detector: it "fired" on a sample if it produced at least one finding, and the sample's
 * {@code expected} list says whether it should have. Near-miss negatives are the point of the
 * corpus; a detector is only as good as the things it correctly ignores.
 * <p>
 * Deliberately bypasses {@link com.inspect.service.InspectionService}: running the corpus must
 * not count as 72 real decisions in the metrics or fire 72 webhooks.
 */
@Service
public class EvalService {

    public static final String CORPUS = "/eval/corpus.jsonl";

    public record Sample(String id, Direction direction, String text, List<String> expected) {}

    private final List<Detector> detectors;
    private final PolicyEngine policy;
    private final ObjectMapper mapper = new ObjectMapper();

    public EvalService(List<Detector> detectors, PolicyEngine policy) {
        this.detectors = List.copyOf(detectors);
        this.policy = policy;
    }

    public List<Sample> corpus() {
        InputStream in = EvalService.class.getResourceAsStream(CORPUS);
        if (in == null) throw new IllegalStateException("Corpus not on classpath: " + CORPUS);
        List<Sample> samples = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                JsonNode node = mapper.readTree(line);
                List<String> expected = new ArrayList<>();
                node.path("expected").forEach(e -> expected.add(e.asString()));
                Direction direction = node.hasNonNull("direction")
                        ? Direction.valueOf(node.get("direction").asString()) : Direction.PROMPT;
                samples.add(new Sample(node.get("id").asString(), direction, node.get("text").asString(), expected));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return samples;
    }

    public EvalReport run() {
        List<Sample> samples = corpus();
        Map<String, int[]> counts = new TreeMap<>();          // detector -> {tp, fp, fn, tn}
        for (Detector d : detectors) counts.put(d.id(), new int[4]);
        List<SampleResult> results = new ArrayList<>(samples.size());

        for (Sample sample : samples) {
            Interaction interaction = new Interaction(sample.id(), "eval", "eval.local",
                    Channel.BROWSER, sample.direction(), sample.text());
            List<String> actual = new ArrayList<>();
            for (Detector d : detectors) {
                if (!d.detect(interaction).isEmpty()) actual.add(d.id());
            }
            List<String> fps = new ArrayList<>();
            List<String> fns = new ArrayList<>();
            for (Detector d : detectors) {
                boolean expected = sample.expected().contains(d.id());
                boolean fired = actual.contains(d.id());
                int[] c = counts.get(d.id());
                if (expected && fired) c[0]++;
                else if (!expected && fired) { c[1]++; fps.add(d.id()); }
                else if (expected) { c[2]++; fns.add(d.id()); }
                else c[3]++;
            }
            String outcome = fps.isEmpty() && fns.isEmpty() ? "PASS"
                    : fps.isEmpty() ? "FALSE_NEGATIVE" : fns.isEmpty() ? "FALSE_POSITIVE" : "BOTH";
            results.add(new SampleResult(sample.id(), sample.direction(), sample.text(),
                    sample.expected(), actual, fps, fns, outcome));
        }

        List<DetectorMetrics> perDetector = new ArrayList<>();
        int tp = 0, fp = 0, fn = 0, tn = 0;
        for (Map.Entry<String, int[]> e : counts.entrySet()) {
            int[] c = e.getValue();
            perDetector.add(DetectorMetrics.of(e.getKey(), c[0], c[1], c[2], c[3]));
            tp += c[0]; fp += c[1]; fn += c[2]; tn += c[3];
        }
        return new EvalReport(Instant.now(), samples.size(), perDetector,
                DetectorMetrics.of("MICRO_TOTAL", tp, fp, fn, tn), results);
    }

    /** Times {@code runs} full inspections (all detectors + policy) of a synthetic ~15 KB document. */
    public LatencyReport latency(int runs) {
        String text = syntheticDocument(1_700);   // ~15 KB, the same size LatencyTest uses
        Interaction interaction = new Interaction("bench", "bench", "claude.ai",
                Channel.BROWSER, Direction.PROMPT, text);

        for (int i = 0; i < 300; i++) inspectOnce(interaction);   // JIT warm-up, same order as LatencyTest

        long[] samples = new long[runs];
        for (int i = 0; i < runs; i++) {
            long t0 = System.nanoTime();
            inspectOnce(interaction);
            samples[i] = System.nanoTime() - t0;
        }
        Arrays.sort(samples);

        Map<String, Double> perDetector = new LinkedHashMap<>();
        int perDetectorRuns = Math.max(20, runs / 5);
        for (Detector d : detectors) {
            long total = 0;
            for (int i = 0; i < perDetectorRuns; i++) {
                long t0 = System.nanoTime();
                d.detect(interaction);
                total += System.nanoTime() - t0;
            }
            perDetector.put(d.id(), round(total / (double) perDetectorRuns / 1e6));
        }
        return new LatencyReport(runs, text.getBytes(StandardCharsets.UTF_8).length,
                round(percentile(samples, 0.50)), round(percentile(samples, 0.95)),
                round(percentile(samples, 0.99)), round(samples[samples.length - 1] / 1e6), perDetector);
    }

    private void inspectOnce(Interaction interaction) {
        List<Finding> findings = new ArrayList<>();
        for (Detector d : detectors) findings.addAll(d.detect(interaction));
        policy.decide(interaction, findings);
    }

    private static double percentile(long[] sorted, double p) {
        int idx = (int) Math.ceil(p * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, idx))] / 1e6;
    }

    private static double round(double ms) {
        return Math.round(ms * 1000) / 1000.0;
    }

    /** Business prose with trigger-free vocabulary, plus one email and one card so the detectors have work to do. */
    static String syntheticDocument(int words) {
        String[] vocab = ("quarterly review customer onboarding roadmap pipeline forecast churn renewal "
                + "margin headcount dashboard latency throughput incident retrospective milestone "
                + "backlog sprint estimate stakeholder procurement invoice region territory partner "
                + "campaign funnel conversion retention churn cohort segment enterprise midmarket").split(" ");
        Random random = new Random(42);
        StringBuilder sb = new StringBuilder(words * 8);
        for (int i = 0; i < words; i++) {
            if (i == words / 3) sb.append("Contact priya.n@northwind-trading.co.uk for the details. ");
            if (i == 2 * words / 3) sb.append("The corporate card 4539 1488 0343 6467 is on file. ");
            sb.append(vocab[random.nextInt(vocab.length)]).append(i % 17 == 16 ? ".\n" : " ");
        }
        return sb.toString();
    }
}
