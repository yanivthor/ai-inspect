package com.inspect.config;

import com.inspect.model.Action;
import com.inspect.model.Channel;
import com.inspect.model.Direction;
import com.inspect.model.Severity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Bound from {@code inspect.*}. The policy lives here, in configuration, because the point of
 * separating the numbers from the logic is that a security team can change what happens to a
 * finding without a deploy - the same reason the detectors never decide an action themselves.
 * <p>
 * {@code @Validated} turns a malformed rule into a startup failure that names the key, instead
 * of a rule that silently never matches. Unknown detector ids are checked separately by
 * {@link com.inspect.policy.PolicyEngine}, which is the only thing that knows what exists.
 */
@Validated
@ConfigurationProperties(prefix = "inspect")
public record InspectProperties(
        @NotNull List<String> sanctionedDestinations,
        @NotEmpty @Valid List<PolicyRule> policies,
        @NotNull @Valid Webhook webhook
) {

    public enum DestinationKind { SANCTIONED, UNSANCTIONED }

    /**
     * One rule. Conditions are AND-ed; an absent condition matches anything. {@code severity}
     * means "at least this severe"; {@code minScore} is a floor on the finding's confidence.
     */
    public record PolicyRule(
            @NotNull Action action,
            @NotBlank String reason,
            @NotNull @Valid When when
    ) {
    }

    public record When(
            String detector,
            Severity severity,
            DestinationKind destination,
            Channel channel,
            Direction direction,
            Double minScore
    ) {
    }

    public record Webhook(
            String url,
            @Min(1) int maxAttempts
    ) {
        public boolean enabled() {
            return url != null && !url.isBlank();
        }
    }
}
