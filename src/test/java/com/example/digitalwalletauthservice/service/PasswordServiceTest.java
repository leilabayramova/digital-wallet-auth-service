package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.config.AuthProperties;
import com.example.digitalwalletauthservice.dto.ChangePasswordRequestDto;
import com.example.digitalwalletauthservice.dto.ForgotPasswordRequestDto;
import com.example.digitalwalletauthservice.dto.ResetPasswordRequestDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.OneTimeTokenType;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.InvalidOneTimeTokenException;
import com.example.digitalwalletauthservice.exception.InvalidPasswordException;
import com.example.digitalwalletauthservice.exception.UserNotFoundException;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordServiceTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private TokenService tokenService;

    @Mock
    private OneTimeTokenService oneTimeTokenService;

    @Mock
    private NotificationService notificationService;

    private PasswordService passwordService;

    @BeforeEach
    void setUp() {
        AuthProperties authProperties = new AuthProperties();
        authProperties.setPasswordResetTtlMinutes(30);

        passwordService = new PasswordService(
                credentialRepository, passwordEncoder, tokenService, oneTimeTokenService,
                notificationService, authProperties
        );
    }

    private CredentialEntity credential() {
        return CredentialEntity.builder()
                .id(1L)
                .userId(10L)
                .email("leila@example.com")
                .passwordHash("old-hash")
                .role(Role.USER)
                .build();
    }

    private ChangePasswordRequestDto changeRequest(String current, String next) {
        ChangePasswordRequestDto requestDto = new ChangePasswordRequestDto();
        requestDto.setCurrentPassword(current);
        requestDto.setNewPassword(next);

        return requestDto;
    }

    // ---------- change ----------

    @Test
    void changePassword_shouldUpdateHashAndRevokeAllSessions() {
        CredentialEntity credential = credential();

        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("old12345", "old-hash")).thenReturn(true);
        when(passwordEncoder.encode("newPass123")).thenReturn("new-hash");

        passwordService.changePassword(10L, changeRequest("old12345", "newPass123"));

        assertThat(credential.getPasswordHash()).isEqualTo("new-hash");
        verify(credentialRepository).save(credential);
        verify(tokenService).revokeAll(10L);
    }

    @Test
    void changePassword_shouldThrow_whenCurrentPasswordIsWrong() {
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.of(credential()));
        when(passwordEncoder.matches("wrong1234", "old-hash")).thenReturn(false);

        assertThatThrownBy(() -> passwordService.changePassword(10L, changeRequest("wrong1234", "newPass123")))
                .isInstanceOf(InvalidPasswordException.class);

        verify(tokenService, never()).revokeAll(any());
    }

    @Test
    void changePassword_shouldThrow_whenNewPasswordEqualsCurrent() {
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.of(credential()));
        when(passwordEncoder.matches("same12345", "old-hash")).thenReturn(true);

        assertThatThrownBy(() -> passwordService.changePassword(10L, changeRequest("same12345", "same12345")))
                .isInstanceOf(InvalidPasswordException.class);
    }

    @Test
    void changePassword_shouldThrow_whenUserDoesNotExist() {
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> passwordService.changePassword(10L, changeRequest("a", "b")))
                .isInstanceOf(UserNotFoundException.class);
    }

    // ---------- forgot ----------

    private ForgotPasswordRequestDto forgotRequest(String email) {
        ForgotPasswordRequestDto requestDto = new ForgotPasswordRequestDto();
        requestDto.setEmail(email);

        return requestDto;
    }

    @Test
    void forgotPassword_shouldIssueTokenAndNotify_whenEmailIsRegistered() {
        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential()));
        when(oneTimeTokenService.issue(eq(10L), eq(OneTimeTokenType.PASSWORD_RESET), eq(Duration.ofMinutes(30))))
                .thenReturn("raw-token");

        passwordService.forgotPassword(forgotRequest(" Leila@Example.com "));

        verify(notificationService).sendPasswordReset("leila@example.com", "raw-token");
    }

    @Test
    void forgotPassword_shouldDoNothingSilently_whenEmailIsUnknown() {
        when(credentialRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        passwordService.forgotPassword(forgotRequest("nobody@example.com"));

        verify(oneTimeTokenService, never()).issue(any(), any(), any());
        verify(notificationService, never()).sendPasswordReset(anyString(), anyString());
    }

    @Test
    void forgotPassword_shouldDoNothing_whenAccountIsDisabled() {
        CredentialEntity credential = credential();
        credential.setEnabled(false);

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));

        passwordService.forgotPassword(forgotRequest("leila@example.com"));

        verify(oneTimeTokenService, never()).issue(any(), any(), any());
    }

    @Test
    void forgotPassword_shouldNotFail_whenNotificationFails() {
        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential()));
        when(oneTimeTokenService.issue(any(), any(), any())).thenReturn("raw-token");
        doThrow(new IllegalStateException("smtp down")).when(notificationService)
                .sendPasswordReset(anyString(), anyString());

        passwordService.forgotPassword(forgotRequest("leila@example.com"));
    }

    // ---------- reset ----------

    private ResetPasswordRequestDto resetRequest() {
        ResetPasswordRequestDto requestDto = new ResetPasswordRequestDto();
        requestDto.setToken("raw-token");
        requestDto.setNewPassword("newPass123");

        return requestDto;
    }

    @Test
    void resetPassword_shouldChangePasswordUnlockAndRevokeSessions() {
        CredentialEntity credential = credential();
        credential.setFailedLoginAttempts(3);
        credential.setLockedUntil(LocalDateTime.now().plusMinutes(10));

        when(oneTimeTokenService.consume("raw-token", OneTimeTokenType.PASSWORD_RESET)).thenReturn(10L);
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.of(credential));
        when(passwordEncoder.encode("newPass123")).thenReturn("new-hash");

        passwordService.resetPassword(resetRequest());

        assertThat(credential.getPasswordHash()).isEqualTo("new-hash");
        assertThat(credential.getFailedLoginAttempts()).isZero();
        assertThat(credential.getLockedUntil()).isNull();
        verify(tokenService).revokeAll(10L);
    }

    @Test
    void resetPassword_shouldPropagate_whenTokenIsInvalid() {
        when(oneTimeTokenService.consume("raw-token", OneTimeTokenType.PASSWORD_RESET))
                .thenThrow(new InvalidOneTimeTokenException("Token is invalid or has expired"));

        assertThatThrownBy(() -> passwordService.resetPassword(resetRequest()))
                .isInstanceOf(InvalidOneTimeTokenException.class);

        verify(credentialRepository, never()).save(any());
    }
}
