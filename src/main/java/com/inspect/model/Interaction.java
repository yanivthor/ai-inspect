package com.inspect.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * One piece of text observed on its way to or from an AI tool.
 *
 * @param interactionId caller-supplied id, used as the idempotency key when decisions are
 *                      published downstream; may be null for ad-hoc calls
 * @param user          who is sending it (opaque; never used for detection)
 * @param destination   host or tool the text is headed to, e.g. {@code chat.openai.com} or an MCP
 *                      server name
 * @param text          the content itself, capped so a detector's cost is bounded
 */
public record Interaction(
        String interactionId,
        @NotBlank String user,
        @NotBlank String destination,
        @NotNull Channel channel,
        @NotNull Direction direction,
        @NotBlank @Size(max = 200_000) String text
) {
}
