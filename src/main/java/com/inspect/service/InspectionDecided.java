package com.inspect.service;

import com.inspect.model.Decision;
import com.inspect.model.Interaction;

/**
 * Published after every decision. In-process today; the production shape is the same record
 * on a Kafka topic keyed by user, consumed by whatever wants to know (webhooks, audit, the
 * analytics that tell a security team which tools people actually use).
 */
public record InspectionDecided(Interaction interaction, Decision decision) {
}
