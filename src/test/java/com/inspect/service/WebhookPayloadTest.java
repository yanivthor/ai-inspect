package com.inspect.service;

import com.inspect.model.Action;
import com.inspect.model.Channel;
import com.inspect.model.Decision;
import com.inspect.model.Direction;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import com.inspect.model.Severity;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WebhookPayloadTest {

    @Test
    void serialisedPayloadDoesNotContainTheText() {
        String text = "my card is 4539 1488 0343 6467 please keep it safe";
        var interaction = new Interaction("i-1", "dave", "claude.ai", Channel.BROWSER, Direction.PROMPT, text);
        var finding = Finding.certain("CREDIT_CARD", Severity.HIGH, 11, 30, "4539 **** 6467", "Luhn-valid");
        var decision = new Decision("i-1", Action.REDACT, List.of(finding),
                "my card is [REDACTED] please keep it safe", "redacted", 3, List.of());
        String json = new ObjectMapper().writeValueAsString(
                WebhookPayload.from(new InspectionDecided(interaction, decision)));
        assertThat(json).doesNotContain("please keep it safe").doesNotContain("4539 1488")
                .doesNotContain("REDACTED").doesNotContain("redactedText");
        assertThat(json).contains("\"interactionId\":\"i-1\"").contains("\"detector\":\"CREDIT_CARD\"")
                .contains("\"user\":\"dave\"").contains("\"latencyMs\":3");
    }
}
