package com.inspect.model;

/**
 * PROMPT is text the user (or an agent on their behalf) is sending to a model or tool.
 * RESPONSE is text coming back - a model reply, a fetched web page, an MCP tool result.
 * <p>
 * The distinction matters for prompt injection: an instruction in a RESPONSE is untrusted input
 * that may be about to be acted on by an agent, which is the dangerous (indirect) case.
 */
public enum Direction { PROMPT, RESPONSE }
