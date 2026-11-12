package com.inspect.eval;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * {@code GET /eval} is the dashboard; {@code /api/eval} and {@code /api/eval/latency} are what it
 * reads. Both recompute on every call against the live detectors, so a code change shows up on
 * the next refresh with no build step.
 */
@Controller
public class EvalController {

    private final EvalService eval;

    public EvalController(EvalService eval) {
        this.eval = eval;
    }

    @GetMapping("/eval")
    public String dashboard() {
        return "forward:/eval.html";
    }

    @GetMapping("/api/eval")
    @ResponseBody
    public EvalReport eval() {
        return eval.run();
    }

    @GetMapping("/api/eval/latency")
    @ResponseBody
    public LatencyReport latency(@RequestParam(defaultValue = "300") int runs) {
        if (runs < 1 || runs > 5_000) throw new ResponseStatusException(BAD_REQUEST, "runs must be 1..5000");
        return eval.latency(runs);
    }
}
