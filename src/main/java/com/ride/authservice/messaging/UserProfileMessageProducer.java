package com.ride.authservice.messaging;

import com.ride.authservice.config.RabbitMQConfig;
import com.ride.authservice.dto.UserProfileRequest;
import com.ride.authservice.service.UserServiceClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.AmqpConnectException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserProfileMessageProducer {

    private final RabbitTemplate rabbitTemplate;
    private final UserServiceClient userServiceClient;

    /**
     * Send user profile creation message to queue with HTTP fallback
     * This ensures the message is persisted even if user-service is down
     * If RabbitMQ is unavailable, falls back to direct HTTP call
     */
    public void sendUserProfileCreationMessage(UserProfileRequest userRequest) {
        try {
            log.info("Attempting to send user profile creation message to queue for email: {}", userRequest.getEmail());

            rabbitTemplate.convertAndSend(
                    RabbitMQConfig.USER_PROFILE_EXCHANGE,
                    RabbitMQConfig.USER_PROFILE_ROUTING_KEY,
                    userRequest
            );

            log.info("✅ User profile creation message queued successfully for email: {}", userRequest.getEmail());

        } catch (AmqpConnectException e) {
            log.warn("⚠️ RabbitMQ is not available - falling back to direct HTTP call for email: {}", userRequest.getEmail());
            fallbackToHttp(userRequest);

        } catch (Exception e) {
            log.error("❌ Failed to send user profile creation message for email: {}", userRequest.getEmail(), e);
            log.warn("⚠️ Attempting HTTP fallback for email: {}", userRequest.getEmail());
            fallbackToHttp(userRequest);
        }
    }

    /**
     * Fallback mechanism: Direct HTTP call to user-service
     * Used when RabbitMQ is unavailable
     */
    private void fallbackToHttp(UserProfileRequest userRequest) {
        try {
            log.info("📞 Using HTTP fallback to create user profile for email: {}", userRequest.getEmail());
            userServiceClient.createUserProfile(userRequest);
            log.info("✅ User profile created via HTTP fallback for email: {}", userRequest.getEmail());
        } catch (Exception httpException) {
            log.error("❌ HTTP fallback also failed for email: {}. User profile creation failed!",
                     userRequest.getEmail(), httpException);
            // Log for manual intervention but don't throw - registration should still succeed
        }
    }
}
