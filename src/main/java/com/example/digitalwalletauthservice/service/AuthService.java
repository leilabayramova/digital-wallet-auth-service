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
import com.example.digitalwalletauthservice.mapper.AuthMapper;
import com.example.digitalwalletauthservice.repository.CredentialRepository;
import com.example.digitalwalletauthservice.repository.RefreshTokenRepository;
import com.example.digitalwalletauthservice.security.JwtService;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Locale;

@Slf4j
@Service
public class AuthService {

    private static final String INVALID_LOGIN_MESSAGE = "Invalid email or password";

    private final CredentialRepository credentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserProfileGateway userProfileGateway;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenService tokenService;
    private final EmailVerificationService emailVerificationService;
    private final AuthProperties authProperties;
    private final Clock clock;

    /** Compared against when the email is unknown so the response time does not reveal whether it exists. */
    private final String dummyPasswordHash;

    public AuthService(
            CredentialRepository credentialRepository,
            RefreshTokenRepository refreshTokenRepository,
            UserProfileGateway userProfileGateway,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            TokenService tokenService,
            EmailVerificationService emailVerificationService,
            AuthProperties authProperties,
            Clock clock
    ) {
        this.credentialRepository = credentialRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userProfileGateway = userProfileGateway;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.tokenService = tokenService;
        this.emailVerificationService = emailVerificationService;
        this.authProperties = authProperties;
        this.clock = clock;
        this.dummyPasswordHash = passwordEncoder.encode("dummy-password-for-timing-equalization");
    }

    /**
     * Intentionally not transactional: the remote call to user-service must not hold a database
     * transaction open. Retrying after a partial failure is safe because the idempotency key is
     * derived from the email.
     */
    public AuthResponseDto register(RegisterRequestDto requestDto) {
        String normalizedEmail = normalizeEmail(requestDto.getEmail());

        if (credentialRepository.existsByEmail(normalizedEmail)) {
            log.warn("Registration failed: email already exists");

            throw new EmailAlreadyExistsException("User already exists with email: " + normalizedEmail);
        }

        UserProfileResponseDto userProfile = userProfileGateway.createUser(
                new CreateUserRequestDto(requestDto.getFullName(), normalizedEmail),
                UserProfileGateway.idempotencyKeyFor(normalizedEmail)
        );

        CredentialEntity credentialEntity = CredentialEntity.builder()
                .userId(userProfile.getId())
                .email(normalizedEmail)
                .passwordHash(passwordEncoder.encode(requestDto.getPassword()))
                .role(Role.USER)
                .build();

        try {
            credentialRepository.saveAndFlush(credentialEntity);
        } catch (DataIntegrityViolationException exception) {
            // concurrent registration with the same email (or user id) won the race
            throw new EmailAlreadyExistsException("User already exists with email: " + normalizedEmail);
        }

        AuditLog.event("REGISTER", credentialEntity.getUserId());
        log.info("User registered successfully. userId={}", credentialEntity.getUserId());

        sendVerificationQuietly(credentialEntity);

        return tokenService.issueTokens(credentialEntity);
    }

    public AuthResponseDto login(LoginRequestDto requestDto) {
        String normalizedEmail = normalizeEmail(requestDto.getEmail());

        CredentialEntity credential = credentialRepository.findByEmail(normalizedEmail).orElse(null);

        if (credential == null) {
            passwordEncoder.matches(requestDto.getPassword(), dummyPasswordHash);

            throw new InvalidCredentialsException(INVALID_LOGIN_MESSAGE);
        }

        LocalDateTime now = LocalDateTime.now(clock);

        if (credential.isLocked(now)) {
            AuditLog.event("LOGIN_BLOCKED_LOCKED", credential.getUserId());

            throw new AccountLockedException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordEncoder.matches(requestDto.getPassword(), credential.getPasswordHash())) {
            registerFailedAttempt(credential, now);

            throw new InvalidCredentialsException(INVALID_LOGIN_MESSAGE);
        }

        if (!credential.isEnabled()) {
            AuditLog.event("LOGIN_BLOCKED_DISABLED", credential.getUserId());

            throw new AccountDisabledException("Account is disabled");
        }

        if (authProperties.isRequireEmailVerification() && !credential.isEmailVerified()) {
            throw new EmailNotVerifiedException("Email address is not verified");
        }

        if (credential.getFailedLoginAttempts() > 0 || credential.getLockedUntil() != null) {
            credential.clearLoginFailures();
            credentialRepository.save(credential);
        }

        AuditLog.event("LOGIN_SUCCESS", credential.getUserId());
        log.info("User logged in successfully. userId={}", credential.getUserId());

        return tokenService.issueTokens(credential);
    }

    /**
     * A revoked token being presented again indicates theft or replay, so every session of the user is
     * revoked. The revocation must survive the exception, hence noRollbackFor.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public AuthResponseDto refresh(RefreshRequestDto requestDto) {
        String tokenHash = jwtService.hashToken(requestDto.getRefreshToken());

        RefreshTokenEntity existingToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token is invalid"));

        if (existingToken.isRevoked()) {
            int revoked = tokenService.revokeAll(existingToken.getUserId());

            AuditLog.event("REFRESH_TOKEN_REUSE_DETECTED", existingToken.getUserId(), "revokedSessions=" + revoked);

            throw new InvalidRefreshTokenException("Refresh token is expired or revoked");
        }

        // atomic: of two concurrent requests with the same token only one gets 1 updated row
        if (refreshTokenRepository.revokeIfUsable(existingToken.getId(), LocalDateTime.now(clock)) == 0) {
            throw new InvalidRefreshTokenException("Refresh token is expired or revoked");
        }

        CredentialEntity credential = credentialRepository.findByUserId(existingToken.getUserId())
                .orElseThrow(() -> new InvalidRefreshTokenException("Associated user no longer exists"));

        if (!credential.isEnabled()) {
            throw new AccountDisabledException("Account is disabled");
        }

        log.info("Access token refreshed. userId={}", credential.getUserId());

        return tokenService.issueTokens(credential);
    }

    @Transactional
    public void logout(LogoutRequestDto requestDto) {
        refreshTokenRepository.findByTokenHash(jwtService.hashToken(requestDto.getRefreshToken()))
                .ifPresent(token -> {
                    token.setRevoked(true);

                    AuditLog.event("LOGOUT", token.getUserId());
                });
    }

    public void logoutAll(JwtUserPrincipal principal) {
        int revoked = tokenService.revokeAll(principal.userId());

        AuditLog.event("LOGOUT_ALL", principal.userId(), "revokedSessions=" + revoked);
    }

    public UserInfoResponseDto getCurrentUser(JwtUserPrincipal principal) {
        return AuthMapper.toUserInfoResponseDto(principal);
    }

    private void registerFailedAttempt(CredentialEntity credential, LocalDateTime now) {
        int attempts = credential.getFailedLoginAttempts() + 1;

        if (attempts >= authProperties.getMaxFailedLoginAttempts()) {
            credential.setFailedLoginAttempts(0);
            credential.setLockedUntil(now.plusMinutes(authProperties.getLockDurationMinutes()));

            AuditLog.event("ACCOUNT_LOCKED", credential.getUserId());
        } else {
            credential.setFailedLoginAttempts(attempts);
        }

        credentialRepository.save(credential);

        log.warn("Login failed: invalid password. userId={}", credential.getUserId());
    }

    private void sendVerificationQuietly(CredentialEntity credential) {
        try {
            emailVerificationService.sendVerification(credential);
        } catch (RuntimeException exception) {
            log.warn("Could not send verification message. userId={}", credential.getUserId(), exception);
        }
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
