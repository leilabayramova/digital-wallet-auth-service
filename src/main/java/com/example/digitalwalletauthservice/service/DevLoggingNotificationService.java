package com.example.digitalwalletauthservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

/**
 * Local development only: prints the one-time token to the log instead of emailing it.
 */
@Slf4j
@Service
@Profile("local")
public class DevLoggingNotificationService implements NotificationService {

    @Override
    public void sendEmailVerification(String email, String token) {
        log.info("[DEV ONLY] Email verification token for {}: {}", email, token);
    }

    @Override
    public void sendPasswordReset(String email, String token) {
        log.info("[DEV ONLY] Password reset token for {}: {}", email, token);
    }
}
