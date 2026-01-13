package com.ride.authservice;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

    @Bean
    public CommandLineRunner run() {
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthServiceApplication.class);
        return args -> logger.info("Auth Service is running...");
    }
}
