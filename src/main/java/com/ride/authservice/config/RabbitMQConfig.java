package com.ride.authservice.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(name = "spring.rabbitmq.enabled", havingValue = "true", matchIfMissing = true)
public class RabbitMQConfig {

    // Queue names
    public static final String USER_PROFILE_QUEUE = "user.profile.queue";
    public static final String USER_PROFILE_EXCHANGE = "user.profile.exchange";
    public static final String USER_PROFILE_ROUTING_KEY = "user.profile.routing.key";

    // Dead Letter Queue configuration
    public static final String USER_PROFILE_DLQ = "user.profile.dlq";
    public static final String USER_PROFILE_DLX = "user.profile.dlx";
    public static final String USER_PROFILE_DLQ_ROUTING_KEY = "user.profile.dlq.routing.key";

    /**
     * Main queue for user profile creation
     */
    @Bean
    public Queue userProfileQueue() {
        return QueueBuilder.durable(USER_PROFILE_QUEUE)
                .withArgument("x-dead-letter-exchange", USER_PROFILE_DLX)
                .withArgument("x-dead-letter-routing-key", USER_PROFILE_DLQ_ROUTING_KEY)
                .withArgument("x-message-ttl", 86400000) // 24 hours TTL
                .build();
    }

    /**
     * Dead Letter Queue for failed messages
     */
    @Bean
    public Queue userProfileDeadLetterQueue() {
        return QueueBuilder.durable(USER_PROFILE_DLQ).build();
    }

    /**
     * Main exchange
     */
    @Bean
    public DirectExchange userProfileExchange() {
        return new DirectExchange(USER_PROFILE_EXCHANGE);
    }

    /**
     * Dead Letter Exchange
     */
    @Bean
    public DirectExchange userProfileDeadLetterExchange() {
        return new DirectExchange(USER_PROFILE_DLX);
    }

    /**
     * Binding main queue to exchange
     */
    @Bean
    public Binding userProfileBinding(Queue userProfileQueue, DirectExchange userProfileExchange) {
        return BindingBuilder.bind(userProfileQueue)
                .to(userProfileExchange)
                .with(USER_PROFILE_ROUTING_KEY);
    }

    /**
     * Binding DLQ to DLX
     */
    @Bean
    public Binding userProfileDLQBinding(Queue userProfileDeadLetterQueue, DirectExchange userProfileDeadLetterExchange) {
        return BindingBuilder.bind(userProfileDeadLetterQueue)
                .to(userProfileDeadLetterExchange)
                .with(USER_PROFILE_DLQ_ROUTING_KEY);
    }

    /**
     * Message converter for JSON serialization
     */
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    /**
     * RabbitTemplate with JSON converter
     */
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(jsonMessageConverter());
        return rabbitTemplate;
    }
}
