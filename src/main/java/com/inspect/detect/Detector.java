package com.inspect.detect;

import com.inspect.model.Finding;
import com.inspect.model.Interaction;

import java.util.List;

/**
 * One detector, one concern. Adding a detector is a class and {@code @Component}; nothing else
 * registers it - {@code InspectionService} injects {@code List<Detector>}.
 * <p>
 * Contract: pure, thread-safe, never throws for any text, and every finding carries an
 * explanation a user could disagree with. A detector that cannot explain its match should
 * report a lower score, not a confident one.
 */
public interface Detector {

    /** Stable id used in findings, policy rules and metrics. Upper snake case. */
    String id();

    List<Finding> detect(Interaction interaction);
}
