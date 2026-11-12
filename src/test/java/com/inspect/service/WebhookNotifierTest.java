package com.inspect.service;

import com.inspect.config.InspectProperties;
import com.inspect.model.Action;
import com.inspect.model.Channel;
import com.inspect.model.Decision;
import com.inspect.model.Direction;
import com.inspect.model.Interaction;
import com.sun.net.httpserver.HttpServer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.web.client.RestClient;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class WebhookNotifierTest {

    private HttpServer server;
    private final AtomicInteger hits = new AtomicInteger();
    private volatile int status = 200;
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/hook", ex -> {
            hits.incrementAndGet();
            ex.getRequestBody().readAllBytes();
            ex.sendResponseHeaders(status, -1);
            ex.close();
        });
        server.start();
    }

    @AfterEach
    void stop() { server.stop(0); }

    private WebhookNotifier notifier(int attempts, int queue) {
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/hook";
        var props = new InspectProperties(List.of(), List.of(), new InspectProperties.Webhook(url, attempts));
        var provider = new StaticListableBeanFactory().getBeanProvider(RestClient.Builder.class);
        return new WebhookNotifier(props, provider, registry, queue);
    }

    private static InspectionDecided event() {
        var i = new Interaction("i-1", "dave", "claude.ai", Channel.BROWSER, Direction.PROMPT, "secret text");
        return new InspectionDecided(i, new Decision("i-1", Action.BLOCK, List.of(), null, "blocked", 1, List.of()));
    }

    @Test
    void clientErrorIsNotRetried() {
        status = 400;
        notifier(3, 10).deliver(event());
        assertThat(hits.get()).isEqualTo(1);
    }

    @Test
    void serverErrorIsRetriedUpToMaxAttempts() {
        status = 503;
        notifier(2, 10).deliver(event());
        assertThat(hits.get()).isEqualTo(2);
    }

    @Test
    void tooManyRequestsIsRetried() {
        status = 429;
        notifier(2, 10).deliver(event());
        assertThat(hits.get()).isEqualTo(2);
    }

    @Test
    void successIsDeliveredOnce() {
        notifier(3, 10).deliver(event());
        assertThat(hits.get()).isEqualTo(1);
    }

    @Test
    void rejectedSubmissionIsCountedAndDoesNotThrow() {
        var n = notifier(1, 1);
        n.shutdown();
        n.on(event());
        assertThat(registry.get("inspect.webhook.dropped").counter().count()).isEqualTo(1.0);
    }
}
