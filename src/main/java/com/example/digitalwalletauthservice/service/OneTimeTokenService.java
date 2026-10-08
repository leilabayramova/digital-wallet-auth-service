package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.entity.OneTimeTokenEntity;
import com.example.digitalwalletauthservice.entity.OneTimeTokenType;
import com.example.digitalwalletauthservice.exception.InvalidOneTimeTokenException;
import com.example.digitalwalletauthservice.repository.OneTimeTokenRepository;
import com.example.digitalwalletauthservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class OneTimeTokenService {

    private static final String INVALID_TOKEN_MESSAGE = "Token is invalid or has expired";

    private final OneTimeTokenRepository oneTimeTokenRepository;
    private final JwtService jwtService;
    private final Clock clock;

    /**
     * Issues a new token and invalidates any earlier unused token of the same type for the user.
     * Only the hash is stored; the raw value is returned once.
     */
    @Transactional
    public String issue(Long userId, OneTimeTokenType type, Duration ttl) {
        oneTimeTokenRepository.invalidateAllUnused(userId, type);

        String rawToken = jwtService.generateRefreshTokenValue();

        oneTimeTokenRepository.save(OneTimeTokenEntity.builder()
                .userId(userId)
                .type(type)
                .tokenHash(jwtService.hashToken(rawToken))
                .expiresAt(LocalDateTime.now(clock).plus(ttl))
                .used(false)
                .build());

        return rawToken;
    }

    /**
     * Atomically consumes the token and returns the owning user id.
     */
    @Transactional
    public Long consume(String rawToken, OneTimeTokenType type) {
        OneTimeTokenEntity token = oneTimeTokenRepository
                .findByTokenHashAndType(jwtService.hashToken(rawToken), type)
                .orElseThrow(() -> new InvalidOneTimeTokenException(INVALID_TOKEN_MESSAGE));

        if (oneTimeTokenRepository.markUsedIfValid(token.getId(), LocalDateTime.now(clock)) == 0) {
            throw new InvalidOneTimeTokenException(INVALID_TOKEN_MESSAGE);
        }

        return token.getUserId();
    }
}
