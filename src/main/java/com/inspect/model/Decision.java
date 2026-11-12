package com.inspect.model;

import java.util.List;

/**
 * The verdict on one interaction.
 *
 * @param redactedText present only when action is REDACT
 * @param explanation  the matched policy's reason, written for the person who will read it
 * @param latencyMs    wall-clock time spent inside the service, so a caller can see the budget
 * @param failedDetectors ids of detectors that threw and so did not inspect this text; empty
 *                     normally. Without it a crashed detector is indistinguishable from "clean"
 */
public record Decision(
        String interactionId,
        Action action,
        List<Finding> findings,
        String redactedText,
        String explanation,
        long latencyMs,
        List<String> failedDetectors
) {
}
