package com.skillstorm.authservice.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "spring.security.oauth2.client.registration.google")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2ClientGoogleConfig {

    // Pull these values from the env vars set in application.yml.
    private String clientId;
    private String clientSecret;

}
