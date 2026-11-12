package com.inspect.controller;

import com.inspect.model.Decision;
import com.inspect.model.Interaction;
import com.inspect.service.InspectionService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api")
public class InspectController {

    private final InspectionService service;

    public InspectController(InspectionService service) {
        this.service = service;
    }

    /** Always 200 with a decision; a BLOCK is a legitimate answer, not an error. */
    @PostMapping("/inspect")
    public Decision inspect(@Valid @RequestBody Interaction interaction) {
        return service.inspect(interaction);
    }

    @GetMapping("/detectors")
    public List<String> detectors() {
        return service.detectorIds();
    }
}
