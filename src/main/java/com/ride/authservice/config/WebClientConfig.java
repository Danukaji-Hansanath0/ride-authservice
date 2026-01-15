package com.ride.authservice.config;

import java.time.Duration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

@Slf4j
@Configuration
public class WebClientConfig {

    @Value("${services.user-service.url}")
    private String userServiceUrl;

    @Value("${webclient.timeout:5000}")
    private int timeout;

    /**
     * Base WebClient for user-service communication
     */
    @Bean(name = "userServiceWebClient")
    public WebClient userServiceWebClient() {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(timeout));

        return WebClient.builder()
                .baseUrl(userServiceUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(logRequest())
                .filter(logResponse())
                .build();
    }

    /**
     * Generic WebClient for other services
     */
    @Bean(name = "genericWebClient")
    public WebClient genericWebClient() {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(timeout));

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(logRequest())
                .filter(logResponse())
                .build();
    }

    /**
     * Log outgoing requests
     */
    private ExchangeFilterFunction logRequest() {
        return ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
            log.debug("Request: {} {}", clientRequest.method(), clientRequest.url());

            clientRequest.headers().forEach((name, values) -> values.forEach(value -> {
                if (name.equalsIgnoreCase("Authorization")) {
                    log.debug("{}=***", name);
                } else {
                    log.debug("{}={}", name, value);
                }
            }));

            return Mono.just(clientRequest);
        });
    }

    /**
     * Log incoming responses
     */
    private ExchangeFilterFunction logResponse() {
        return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
            log.debug("Response status: {}", clientResponse.statusCode());
            return Mono.just(clientResponse);
        });
    }
}
