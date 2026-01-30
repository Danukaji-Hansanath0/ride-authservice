package com.ride.authservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.*;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    private String issuerUri;

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        final String oauthSchemeName = "oauth2";

        return new OpenAPI()
                .info(new Info()
                        .title("Auth Service API")
                        .version("1.0.0")
                        .description("Authentication and Authorization Service APIs for Ride Platform")
                        .contact(new Contact()
                                .name("Ride Team")
                                .email("support@ride.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                // Use the current request host (localhost, VPS IP, or domain) automatically.
                .servers(List.of(new Server().url("/").description("Current Server")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Enter JWT Bearer token"))
                        .addSecuritySchemes(oauthSchemeName,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.OAUTH2)
                                        .description("OAuth2 Authentication via Keycloak")
                                        .flows(new OAuthFlows()
                                                .authorizationCode(new OAuthFlow()
                                                        .authorizationUrl(issuerUri + "/protocol/openid-connect/auth")
                                                        .tokenUrl(issuerUri + "/protocol/openid-connect/token")
                                                        .scopes(new Scopes()
                                                                .addString("openid", "OpenID Connect scope")
                                                                .addString("profile", "User profile information")
                                                                .addString("email", "User email address")
                                                                .addString("roles", "User roles"))))));
    }
}

/*
 * IMPORTANT: Keycloak Configuration Required
 * ==========================================
 *
 * For Swagger UI OAuth2 to work, you must configure the Keycloak client 'auth2-client':
 *
 * 1. Login to Keycloak Admin Console: https://auth.rydeflexi.com/admin
 * 2. Navigate to: Realm 'user-authentication' → Clients → 'auth2-client'
 * 3. Add these Valid Redirect URIs:
 *    - http://localhost:8081/swagger-ui/*
 *    - http://localhost:8081/swagger-ui/oauth2-redirect.html
 *    - https://api.rydeflexi.com/auth-service/swagger-ui/*
 * 4. Add Web Origins:
 *    - http://localhost:8081
 *    - https://api.rydeflexi.com
 *    - +
 * 5. Save and restart the service
 *
 * See KEYCLOAK_SWAGGER_FIX.md for detailed instructions
 */
