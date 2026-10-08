package com.example.digitalwalletauthservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

/**
 * Placeholder until a real email provider is integrated: replace this bean with an SMTP or API based
 * implementation of {@link NotificationService}.
 */
@Slf4j
@Service
@Profile("!local")
public class NoOpNotificationService implements NotificationService {

    @Override
    public void sendEmailVerification(String email, String token) {
        log.warn("No email provider configured: verification message was not delivered");
    }

    @Override
    public void sendPasswordReset(String email, String token) {
        log.warn("No email provider configured: password reset message was not delivered");
    }
}
