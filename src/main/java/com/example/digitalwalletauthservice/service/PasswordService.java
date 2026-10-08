package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.config.AuthProperties;
import com.example.digitalwalletauthservice.dto.ChangePasswordRequestDto;
import com.example.digitalwalletauthservice.dto.ForgotPasswordRequestDto;
import com.example.digitalwalletauthservice.dto.ResetPasswordRequestDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.OneTimeTokenType;
import com.example.digitalwalletauthservice.exception.InvalidOneTimeTokenException;
import com.example.digitalwalletauthservice.exception.InvalidPasswordException;
import com.example.digitalwalletauthservice.exception.UserNotFoundException;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final OneTimeTokenService oneTimeTokenService;
    private final NotificationService notificationService;
    private final AuthProperties authProperties;

    @Transactional
    public void changePassword(Long userId, ChangePasswordRequestDto requestDto) {
        CredentialEntity credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(requestDto.getCurrentPassword(), credential.getPasswordHash())) {
            AuditLog.event("PASSWORD_CHANGE_REJECTED", userId);

            throw new InvalidPasswordException("Current password is incorrect");
        }

        if (requestDto.getCurrentPassword().equals(requestDto.getNewPassword())) {
            throw new InvalidPasswordException("New password must be different from the current password");
        }

        credential.setPasswordHash(passwordEncoder.encode(requestDto.getNewPassword()));
        credentialRepository.save(credential);

        tokenService.revokeAll(userId);

        AuditLog.event("PASSWORD_CHANGED", userId);
    }

    /**
     * Always completes silently so the response never reveals whether the email is registered.
     */
    public void forgotPassword(ForgotPasswordRequestDto requestDto) {
        String normalizedEmail = requestDto.getEmail().trim().toLowerCase(Locale.ROOT);

        credentialRepository.findByEmail(normalizedEmail)
                .filter(CredentialEntity::isEnabled)
                .ifPresent(credential -> {
                    String token = oneTimeTokenService.issue(
                            credential.getUserId(),
                            OneTimeTokenType.PASSWORD_RESET,
                            Duration.ofMinutes(authProperties.getPasswordResetTtlMinutes())
                    );

                    try {
                        notificationService.sendPasswordReset(credential.getEmail(), token);
                    } catch (RuntimeException exception) {
                        log.warn("Could not send password reset message. userId={}", credential.getUserId(), exception);
                    }

                    AuditLog.event("PASSWORD_RESET_REQUESTED", credential.getUserId());
                });
    }

    @Transactional
    public void resetPassword(ResetPasswordRequestDto requestDto) {
        Long userId = oneTimeTokenService.consume(requestDto.getToken(), OneTimeTokenType.PASSWORD_RESET);

        CredentialEntity credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new InvalidOneTimeTokenException("Token is invalid or has expired"));

        credential.setPasswordHash(passwordEncoder.encode(requestDto.getNewPassword()));
        credential.clearLoginFailures();
        credentialRepository.save(credential);

        tokenService.revokeAll(userId);

        AuditLog.event("PASSWORD_RESET_COMPLETED", userId);
    }
}
