package com.example.digitalwalletauthservice.config;

import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    @Positive
    private int maxFailedLoginAttempts = 5;

    @Positive
    private long lockDurationMinutes = 15;

    @Positive
    private long passwordResetTtlMinutes = 30;

    @Positive
    private long emailVerificationTtlMinutes = 1440;

    private boolean requireEmailVerification = false;

    private int cleanupRetentionDays = 7;

    private BootstrapAdmin bootstrapAdmin = new BootstrapAdmin();

    @Getter
    @Setter
    public static class BootstrapAdmin {
        private String email;
        private String password;
        private String fullName = "Administrator";

        public boolean isConfigured() {
            return email != null && !email.isBlank() && password != null && !password.isBlank();
        }
    }
}
