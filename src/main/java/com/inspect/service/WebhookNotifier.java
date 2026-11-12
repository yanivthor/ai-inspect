package com.inspect.service;

import com.inspect.config.InspectProperties;
import com.inspect.model.Action;
import org.slf4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Posts BLOCK and REDACT decisions to a configured URL, off the request thread.
 * <p>
 * Off the request thread because a customer's webhook endpoint is the slowest, least reliable
 * component in the whole path and must never add to the latency a user feels. Retries with
 * backoff because the alternative - dropping a block event because a receiver blipped - is an
 * audit gap nobody notices until an incident. In production this listener is a separate Kafka
 * consumer group on the decisions topic, which gives durability and replay for free; the
 * in-process executor is the laptop-sized stand-in for that.
 */
@Component
public class WebhookNotifier {

    private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);

    private final InspectProperties.Webhook config;
    private final RestClient client;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "webhook-notifier");
        t.setDaemon(true);
        return t;
    });

    public WebhookNotifier(InspectProperties properties, ObjectProvider<RestClient.Builder> builder) {
        this.config = properties.webhook();
        this.client = builder.getIfAvailable(RestClient::builder).build();
        if (config.enabled()) log.info("Webhook delivery to {} (max {} attempts)", config.url(), config.maxAttempts());
        else log.info("Webhook delivery disabled - set INSPECT_WEBHOOK_URL to enable");
    }

    @EventListener
    public void on(InspectionDecided event) {
        if (!config.enabled()) return;
        Action action = event.decision().action();
        if (action != Action.BLOCK && action != Action.REDACT) return;
        executor.submit(() -> deliver(event));
    }

    private void deliver(InspectionDecided event) {
        for (int attempt = 1; attempt <= config.maxAttempts(); attempt++) {
            try {
                client.post().uri(config.url()).body(event).retrieve().toBodilessEntity();
                return;
            } catch (RuntimeException e) {
                log.warn("Webhook attempt {}/{} failed: {}", attempt, config.maxAttempts(), e.getMessage());
                try {
                    Thread.sleep(250L * (1L << (attempt - 1)));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
        log.error("Webhook delivery gave up for interaction {}", event.interaction().interactionId());
    }
}
