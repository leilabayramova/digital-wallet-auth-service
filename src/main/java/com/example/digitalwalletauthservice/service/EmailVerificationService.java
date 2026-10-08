package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.config.AuthProperties;
import com.example.digitalwalletauthservice.dto.VerifyEmailRequestDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.OneTimeTokenType;
import com.example.digitalwalletauthservice.exception.InvalidOneTimeTokenException;
import com.example.digitalwalletauthservice.exception.InvalidOperationException;
import com.example.digitalwalletauthservice.exception.UserNotFoundException;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final CredentialRepository credentialRepository;
    private final OneTimeTokenService oneTimeTokenService;
    private final NotificationService notificationService;
    private final AuthProperties authProperties;

    public void sendVerification(CredentialEntity credential) {
        String token = oneTimeTokenService.issue(
                credential.getUserId(),
                OneTimeTokenType.EMAIL_VERIFICATION,
                Duration.ofMinutes(authProperties.getEmailVerificationTtlMinutes())
        );

        notificationService.sendEmailVerification(credential.getEmail(), token);
    }

    @Transactional
    public void verify(VerifyEmailRequestDto requestDto) {
        Long userId = oneTimeTokenService.consume(requestDto.getToken(), OneTimeTokenType.EMAIL_VERIFICATION);

        CredentialEntity credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new InvalidOneTimeTokenException("Token is invalid or has expired"));

        credential.setEmailVerified(true);
        credentialRepository.save(credential);

        AuditLog.event("EMAIL_VERIFIED", userId);
    }

    public void resend(Long userId) {
        CredentialEntity credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (credential.isEmailVerified()) {
            throw new InvalidOperationException("Email is already verified");
        }

        sendVerification(credential);

        AuditLog.event("EMAIL_VERIFICATION_RESENT", userId);
    }
}
