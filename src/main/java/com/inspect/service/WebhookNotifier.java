package com.inspect.service;

import com.inspect.config.InspectProperties;
import com.inspect.model.Action;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Posts BLOCK and REDACT decisions to a configured URL, off the request thread.
 * <p>
 * Off the request thread because a customer's webhook endpoint is the slowest, least reliable
 * component in the whole path and must never add to the latency a user feels. Retries with
 * backoff because the alternative - dropping a block event because a receiver blipped - is an
 * audit gap nobody notices until an incident. Only failures that can plausibly clear are
 * retried (5xx, 429, network errors); a 400 or 404 will fail identically every time.
 * <p>
 * The queue is bounded: a dead receiver must not grow the heap without limit, and a full queue
 * drops the event and counts it ({@code inspect.webhook.dropped}) rather than blocking or
 * throwing into the request that made the decision. In production this listener is a separate
 * Kafka consumer group on the decisions topic, which gives durability and replay for free; the
 * in-process executor is the laptop-sized stand-in for that.
 */
@Component
public class WebhookNotifier {

    private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);

    static final int QUEUE_CAPACITY = 1_000;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(5);

    private final InspectProperties.Webhook config;
    private final RestClient client;
    private final Counter dropped;
    private final ThreadPoolExecutor executor;

    @Autowired
    public WebhookNotifier(InspectProperties properties, ObjectProvider<RestClient.Builder> builder,
                           MeterRegistry registry) {
        this(properties, builder, registry, QUEUE_CAPACITY);
    }

    WebhookNotifier(InspectProperties properties, ObjectProvider<RestClient.Builder> builder,
                    MeterRegistry registry, int queueCapacity) {
        this.config = properties.webhook();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build());
        factory.setReadTimeout(READ_TIMEOUT);
        this.client = builder.getIfAvailable(RestClient::builder).requestFactory(factory).build();
        this.dropped = Counter.builder("inspect.webhook.dropped")
                .description("Webhook events discarded because the delivery queue was full")
                .register(registry);
        this.executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity), r -> {
                    Thread t = new Thread(r, "webhook-notifier");
                    t.setDaemon(true);
                    return t;
                });
        if (config.enabled()) log.info("Webhook delivery to {} (max {} attempts)", config.url(), config.maxAttempts());
        else log.info("Webhook delivery disabled - set INSPECT_WEBHOOK_URL to enable");
    }

    @EventListener
    public void on(InspectionDecided event) {
        if (!config.enabled()) return;
        Action action = event.decision().action();
        if (action != Action.BLOCK && action != Action.REDACT) return;
        try {
            executor.execute(() -> deliver(event));
        } catch (RejectedExecutionException e) {
            dropped.increment();
            log.error("Webhook queue full or stopped; dropped event for interaction {}", event.decision().interactionId());
        }
    }

    /** Package-private so tests can drive delivery synchronously. */
    void deliver(InspectionDecided event) {
        WebhookPayload payload = WebhookPayload.from(event);
        int max = config.maxAttempts();
        for (int attempt = 1; attempt <= max; attempt++) {
            try {
                client.post().uri(config.url()).body(payload).retrieve().toBodilessEntity();
                return;
            } catch (RuntimeException e) {
                boolean retryable = isRetryable(e);
                log.warn("Webhook attempt {}/{} failed ({}): {}", attempt, max,
                        retryable ? "retryable" : "permanent", e.getMessage());
                if (!retryable || attempt == max) break;
                try {
                    Thread.sleep(250L * (1L << (attempt - 1)));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
        log.error("Webhook delivery gave up for interaction {}", payload.interactionId());
    }

    static boolean isRetryable(RuntimeException e) {
        if (e instanceof HttpServerErrorException || e instanceof ResourceAccessException) return true;
        return e instanceof HttpClientErrorException c && c.getStatusCode().value() == HttpStatus.TOO_MANY_REQUESTS.value();
    }

    @PreDestroy
    void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow();
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
