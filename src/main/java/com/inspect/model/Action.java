package com.inspect.model;

/**
 * What the enforcing surface should do. Ordered from least to most intrusive.
 * NUDGE lets the interaction continue but shows the user why it was flagged, with a way to
 * disagree - the default posture; BLOCK is the exception, not the rule.
 */
public enum Action { ALLOW, NUDGE, REDACT, BLOCK }
