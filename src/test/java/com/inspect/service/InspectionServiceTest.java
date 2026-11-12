package com.inspect.service;

import com.inspect.detect.Detector;
import com.inspect.model.Action;
import com.inspect.model.Finding;
import com.inspect.model.Interaction;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.inspect.Texts.prompt;
import static org.assertj.core.api.Assertions.assertThat;

class InspectionServiceTest {

    private static final Detector EXPLODING = new Detector() {
        public String id() { return "EXPLODING"; }
        public List<Finding> detect(Interaction i) { throw new IllegalStateException("boom"); }
    };

    @Test
    void failedDetectorIsListedAndRequestStillSucceeds() {
        var service = TestServices.service(new SimpleMeterRegistry(), List.of(EXPLODING));
        var decision = service.inspect(prompt("Quarterly revenue grew four percent."));
        assertThat(decision.action()).isEqualTo(Action.ALLOW);
        assertThat(decision.failedDetectors()).containsExactly("EXPLODING");
    }

    @Test
    void failedDetectorsIsEmptyNormally() {
        var service = TestServices.service(new SimpleMeterRegistry());
        assertThat(service.inspect(prompt("hello there")).failedDetectors()).isEmpty();
    }
}
