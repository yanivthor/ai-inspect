package com.inspect.service;

import com.inspect.model.Action;
import com.inspect.model.Channel;
import com.inspect.model.Decision;
import com.inspect.model.Direction;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;

import java.util.List;

/**
 * What a webhook receiver is sent. Deliberately not {@link InspectionDecided}: that carries the
 * interaction's full text (and the redacted text), and sending the sensitive content to an
 * external endpoint in order to report that it was sensitive would defeat the product. Findings
 * carry only their masked evidence and offsets.
 */
public record WebhookPayload(
        String interactionId,
        String user,
        String destination,
        Channel channel,
        Direction direction,
        Action action,
        String explanation,
        long latencyMs,
        List<FindingView> findings
) {

    public record FindingView(String detector, Severity severity, int start, int end, String evidence, double score) {
        static FindingView of(Finding f) {
            return new FindingView(f.detector(), f.severity(), f.start(), f.end(), f.evidence(), f.score());
        }
    }

    public static WebhookPayload from(InspectionDecided event) {
        Interaction i = event.interaction();
        Decision d = event.decision();
        return new WebhookPayload(d.interactionId(), i.user(), i.destination(), i.channel(), i.direction(),
                d.action(), d.explanation(), d.latencyMs(),
                d.findings().stream().map(FindingView::of).toList());
    }
}
