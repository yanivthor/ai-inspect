package com.inspect;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class InspectApplication {
    public static void main(String[] args) {
        SpringApplication.run(InspectApplication.class, args);
    }
}
