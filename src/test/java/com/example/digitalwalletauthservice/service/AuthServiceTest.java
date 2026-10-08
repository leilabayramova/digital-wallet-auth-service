package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.client.UserProfileGateway;
import com.example.digitalwalletauthservice.config.AuthProperties;
import com.example.digitalwalletauthservice.dto.AuthResponseDto;
import com.example.digitalwalletauthservice.dto.CreateUserRequestDto;
import com.example.digitalwalletauthservice.dto.LoginRequestDto;
import com.example.digitalwalletauthservice.dto.LogoutRequestDto;
import com.example.digitalwalletauthservice.dto.RefreshRequestDto;
import com.example.digitalwalletauthservice.dto.RegisterRequestDto;
import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.dto.UserProfileResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.RefreshTokenEntity;
import com.example.digitalwalletauthservice.entity.Role;
import com.example.digitalwalletauthservice.exception.AccountDisabledException;
import com.example.digitalwalletauthservice.exception.AccountLockedException;
import com.example.digitalwalletauthservice.exception.EmailAlreadyExistsException;
import com.example.digitalwalletauthservice.exception.EmailNotVerifiedException;
import com.example.digitalwalletauthservice.exception.InvalidCredentialsException;
import com.example.digitalwalletauthservice.exception.InvalidRefreshTokenException;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import com.example.digitalwalletauthservice.repository.RefreshTokenRepository;
import com.example.digitalwalletauthservice.security.JwtService;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserProfileGateway userProfileGateway;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private TokenService tokenService;

    @Mock
    private EmailVerificationService emailVerificationService;

    private AuthProperties authProperties;

    private AuthService authService;

    private final AuthResponseDto tokens = AuthResponseDto.builder()
            .accessToken("access-token")
            .refreshToken("refresh-token")
            .tokenType("Bearer")
            .expiresInSeconds(900)
            .build();

    @BeforeEach
    void setUp() {
        authProperties = new AuthProperties();
        authProperties.setMaxFailedLoginAttempts(3);
        authProperties.setLockDurationMinutes(15);

        lenient().when(passwordEncoder.encode(anyString())).thenReturn("encoded");

        authService = new AuthService(
                credentialRepository,
                refreshTokenRepository,
                userProfileGateway,
                passwordEncoder,
                jwtService,
                tokenService,
                emailVerificationService,
                authProperties,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    private CredentialEntity credential() {
        return CredentialEntity.builder()
                .id(1L)
                .userId(10L)
                .email("leila@example.com")
                .passwordHash("stored-hash")
                .role(Role.USER)
                .build();
    }

    private LoginRequestDto loginRequest(String password) {
        LoginRequestDto requestDto = new LoginRequestDto();
        requestDto.setEmail("  Leila@Example.com ");
        requestDto.setPassword(password);

        return requestDto;
    }

    // ---------- register ----------

    @Test
    void register_shouldCreateCredentialAndReturnTokens_whenEmailDoesNotExist() {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("  Leila@Example.com ");
        requestDto.setPassword("password123");

        UserProfileResponseDto profile = new UserProfileResponseDto();
        profile.setId(10L);

        when(credentialRepository.existsByEmail("leila@example.com")).thenReturn(false);
        when(userProfileGateway.createUser(any(CreateUserRequestDto.class), anyString())).thenReturn(profile);
        when(tokenService.issueTokens(any(CredentialEntity.class))).thenReturn(tokens);

        AuthResponseDto result = authService.register(requestDto);

        assertThat(result).isSameAs(tokens);

        ArgumentCaptor<CredentialEntity> captor = ArgumentCaptor.forClass(CredentialEntity.class);
        verify(credentialRepository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getUserId()).isEqualTo(10L);
        assertThat(captor.getValue().getEmail()).isEqualTo("leila@example.com");
        assertThat(captor.getValue().getRole()).isEqualTo(Role.USER);
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("encoded");
        verify(emailVerificationService).sendVerification(captor.getValue());
    }

    @Test
    void register_shouldThrow_whenEmailAlreadyExists() {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        when(credentialRepository.existsByEmail("leila@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(requestDto)).isInstanceOf(EmailAlreadyExistsException.class);

        verify(userProfileGateway, never()).createUser(any(), anyString());
    }

    @Test
    void register_shouldThrowEmailAlreadyExists_whenConcurrentRegistrationWinsTheRace() {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        UserProfileResponseDto profile = new UserProfileResponseDto();
        profile.setId(10L);

        when(credentialRepository.existsByEmail("leila@example.com")).thenReturn(false);
        when(userProfileGateway.createUser(any(), anyString())).thenReturn(profile);
        doThrow(new DataIntegrityViolationException("duplicate")).when(credentialRepository)
                .saveAndFlush(any(CredentialEntity.class));

        assertThatThrownBy(() -> authService.register(requestDto)).isInstanceOf(EmailAlreadyExistsException.class);

        verify(tokenService, never()).issueTokens(any());
    }

    @Test
    void register_shouldStillSucceed_whenVerificationMessageFails() {
        RegisterRequestDto requestDto = new RegisterRequestDto();
        requestDto.setFullName("Leila");
        requestDto.setEmail("leila@example.com");
        requestDto.setPassword("password123");

        UserProfileResponseDto profile = new UserProfileResponseDto();
        profile.setId(10L);

        when(userProfileGateway.createUser(any(), anyString())).thenReturn(profile);
        doThrow(new IllegalStateException("smtp down")).when(emailVerificationService)
                .sendVerification(any(CredentialEntity.class));
        when(tokenService.issueTokens(any())).thenReturn(tokens);

        assertThat(authService.register(requestDto)).isSameAs(tokens);
    }

    // ---------- login ----------

    @Test
    void login_shouldReturnTokens_whenCredentialsAreValid() {
        CredentialEntity credential = credential();

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password123", "stored-hash")).thenReturn(true);
        when(tokenService.issueTokens(credential)).thenReturn(tokens);

        assertThat(authService.login(loginRequest("password123"))).isSameAs(tokens);
    }

    @Test
    void login_shouldThrowAndStillHashPassword_whenEmailNotFound() {
        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(loginRequest("password123")))
                .isInstanceOf(InvalidCredentialsException.class);

        // dummy comparison keeps the timing of unknown and known emails similar
        verify(passwordEncoder).matches(eq("password123"), anyString());
        verify(tokenService, never()).issueTokens(any());
    }

    @Test
    void login_shouldCountFailedAttempt_whenPasswordIsInvalid() {
        CredentialEntity credential = credential();

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrong", "stored-hash")).thenReturn(false);

        assertThatThrownBy(() -> authService.login(loginRequest("wrong")))
                .isInstanceOf(InvalidCredentialsException.class);

        assertThat(credential.getFailedLoginAttempts()).isEqualTo(1);
        assertThat(credential.getLockedUntil()).isNull();
        verify(credentialRepository).save(credential);
    }

    @Test
    void login_shouldLockAccount_whenMaxFailedAttemptsReached() {
        CredentialEntity credential = credential();
        credential.setFailedLoginAttempts(2);

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrong", "stored-hash")).thenReturn(false);

        assertThatThrownBy(() -> authService.login(loginRequest("wrong")))
                .isInstanceOf(InvalidCredentialsException.class);

        assertThat(credential.getFailedLoginAttempts()).isZero();
        assertThat(credential.getLockedUntil())
                .isEqualTo(LocalDateTime.ofInstant(NOW, ZoneOffset.UTC).plusMinutes(15));
    }

    @Test
    void login_shouldRejectWithoutCheckingPassword_whenAccountIsLocked() {
        CredentialEntity credential = credential();
        credential.setLockedUntil(LocalDateTime.ofInstant(NOW, ZoneOffset.UTC).plusMinutes(5));

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));

        assertThatThrownBy(() -> authService.login(loginRequest("password123")))
                .isInstanceOf(AccountLockedException.class);

        verify(passwordEncoder, never()).matches("password123", "stored-hash");
    }

    @Test
    void login_shouldAcceptCorrectPasswordAndResetCounters_whenLockHasExpired() {
        CredentialEntity credential = credential();
        credential.setFailedLoginAttempts(2);
        credential.setLockedUntil(LocalDateTime.ofInstant(NOW, ZoneOffset.UTC).minusMinutes(1));

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password123", "stored-hash")).thenReturn(true);
        when(tokenService.issueTokens(credential)).thenReturn(tokens);

        authService.login(loginRequest("password123"));

        assertThat(credential.getFailedLoginAttempts()).isZero();
        assertThat(credential.getLockedUntil()).isNull();
        verify(credentialRepository).save(credential);
    }

    @Test
    void login_shouldThrowDisabled_whenAccountIsDisabled() {
        CredentialEntity credential = credential();
        credential.setEnabled(false);

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password123", "stored-hash")).thenReturn(true);

        assertThatThrownBy(() -> authService.login(loginRequest("password123")))
                .isInstanceOf(AccountDisabledException.class);

        verify(tokenService, never()).issueTokens(any());
    }

    @Test
    void login_shouldThrow_whenEmailVerificationRequiredButMissing() {
        authProperties.setRequireEmailVerification(true);
        CredentialEntity credential = credential();

        when(credentialRepository.findByEmail("leila@example.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password123", "stored-hash")).thenReturn(true);

        assertThatThrownBy(() -> authService.login(loginRequest("password123")))
                .isInstanceOf(EmailNotVerifiedException.class);
    }

    // ---------- refresh ----------

    private RefreshRequestDto refreshRequest() {
        RefreshRequestDto requestDto = new RefreshRequestDto();
        requestDto.setRefreshToken("raw-refresh");

        return requestDto;
    }

    private RefreshTokenEntity storedToken(boolean revoked) {
        return RefreshTokenEntity.builder()
                .id(5L)
                .userId(10L)
                .tokenHash("hash")
                .revoked(revoked)
                .expiresAt(LocalDateTime.ofInstant(NOW, ZoneOffset.UTC).plusDays(1))
                .build();
    }

    @Test
    void refresh_shouldRotateToken_whenRefreshTokenIsValid() {
        CredentialEntity credential = credential();

        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.of(storedToken(false)));
        when(refreshTokenRepository.revokeIfUsable(eq(5L), any(LocalDateTime.class))).thenReturn(1);
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.of(credential));
        when(tokenService.issueTokens(credential)).thenReturn(tokens);

        assertThat(authService.refresh(refreshRequest())).isSameAs(tokens);
    }

    @Test
    void refresh_shouldThrow_whenTokenNotFound() {
        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh(refreshRequest()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void refresh_shouldRevokeAllSessions_whenRevokedTokenIsReused() {
        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.of(storedToken(true)));
        when(tokenService.revokeAll(10L)).thenReturn(2);

        assertThatThrownBy(() -> authService.refresh(refreshRequest()))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(tokenService).revokeAll(10L);
        verify(tokenService, never()).issueTokens(any());
    }

    @Test
    void refresh_shouldThrow_whenTokenIsExpiredOrLostTheRace() {
        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.of(storedToken(false)));
        when(refreshTokenRepository.revokeIfUsable(eq(5L), any(LocalDateTime.class))).thenReturn(0);

        assertThatThrownBy(() -> authService.refresh(refreshRequest()))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(tokenService, never()).issueTokens(any());
    }

    @Test
    void refresh_shouldThrow_whenUserNoLongerExists() {
        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.of(storedToken(false)));
        when(refreshTokenRepository.revokeIfUsable(eq(5L), any(LocalDateTime.class))).thenReturn(1);
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh(refreshRequest()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void refresh_shouldThrowDisabled_whenAccountWasDisabled() {
        CredentialEntity credential = credential();
        credential.setEnabled(false);

        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.of(storedToken(false)));
        when(refreshTokenRepository.revokeIfUsable(eq(5L), any(LocalDateTime.class))).thenReturn(1);
        when(credentialRepository.findByUserId(10L)).thenReturn(Optional.of(credential));

        assertThatThrownBy(() -> authService.refresh(refreshRequest()))
                .isInstanceOf(AccountDisabledException.class);
    }

    // ---------- logout ----------

    @Test
    void logout_shouldRevokeToken_whenTokenExists() {
        RefreshTokenEntity token = storedToken(false);
        LogoutRequestDto requestDto = new LogoutRequestDto();
        requestDto.setRefreshToken("raw-refresh");

        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.of(token));

        authService.logout(requestDto);

        assertThat(token.isRevoked()).isTrue();
    }

    @Test
    void logout_shouldBeSilent_whenTokenIsUnknown() {
        LogoutRequestDto requestDto = new LogoutRequestDto();
        requestDto.setRefreshToken("raw-refresh");

        when(jwtService.hashToken("raw-refresh")).thenReturn("hash");
        when(refreshTokenRepository.findByTokenHash("hash")).thenReturn(Optional.empty());

        authService.logout(requestDto);
    }

    @Test
    void logoutAll_shouldRevokeEverySessionOfUser() {
        authService.logoutAll(new JwtUserPrincipal(10L, "leila@example.com", Role.USER));

        verify(tokenService).revokeAll(10L);
    }

    // ---------- me ----------

    @Test
    void getCurrentUser_shouldMapPrincipalToDto() {
        UserInfoResponseDto result = authService.getCurrentUser(
                new JwtUserPrincipal(10L, "leila@example.com", Role.ADMIN)
        );

        assertThat(result.getUserId()).isEqualTo(10L);
        assertThat(result.getEmail()).isEqualTo("leila@example.com");
        assertThat(result.getRole()).isEqualTo(Role.ADMIN);
        verify(credentialRepository, never()).findByUserId(anyLong());
    }
}
