package com.inspect.service;

import com.inspect.model.Channel;
import com.inspect.model.Direction;
import com.inspect.model.Interaction;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

class LatencyTest {

    private static final String[] WORDS = ("the quarterly review of customer onboarding showed steady progress across regions "
            + "while support volumes remained flat and renewals held up better than the team had forecast so we agreed "
            + "to keep the current plan and revisit pricing after the next planning cycle with finance and sales").split(" ");

    private static String prose(int words) {
        Random r = new Random(42);
        StringBuilder b = new StringBuilder(words * 6);
        for (int i = 0; i < words; i++) {
            b.append(WORDS[r.nextInt(WORDS.length)]).append(i % 15 == 14 ? ".\n" : " ");
            if (i == words / 3) b.append("Contact dave@acme.co.uk about it. ");
            if (i == 2 * words / 3) b.append("Card 4539 1488 0343 6467 was used. ");
        }
        return b.toString();
    }

    @Test
    void p95StaysUnderTwentyMilliseconds() {
        var registry = new SimpleMeterRegistry();
        var service = TestServices.service(registry);
        var interaction = new Interaction("lat", "dave", "claude.ai", Channel.BROWSER, Direction.PROMPT, prose(3000));
        assertThat(interaction.text().length()).isGreaterThan(14_000);

        for (int i = 0; i < 200; i++) service.inspect(interaction);

        double[] ms = new double[1000];
        for (int i = 0; i < ms.length; i++) {
            long t = System.nanoTime();
            service.inspect(interaction);
            ms[i] = (System.nanoTime() - t) / 1e6;
        }
        Arrays.sort(ms);
        double p50 = ms[499], p95 = ms[949], p99 = ms[989];
        System.out.printf("LATENCY (15 KB text, 7 detectors): p50=%.3f ms  p95=%.3f ms  p99=%.3f ms%n", p50, p95, p99);

        assertThat(p95).isLessThan(20.0);
        assertThat(registry.get("inspect.latency").timer().count()).isEqualTo(1200);
    }
}
