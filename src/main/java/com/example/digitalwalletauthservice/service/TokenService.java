package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.config.JwtProperties;
import com.example.digitalwalletauthservice.dto.AuthResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.entity.RefreshTokenEntity;
import com.example.digitalwalletauthservice.mapper.AuthMapper;
import com.example.digitalwalletauthservice.repository.RefreshTokenRepository;
import com.example.digitalwalletauthservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final Clock clock;

    @Transactional
    public AuthResponseDto issueTokens(CredentialEntity credential) {
        String accessToken = jwtService.generateAccessToken(
                credential.getUserId(), credential.getEmail(), credential.getRole()
        );
        String refreshTokenValue = jwtService.generateRefreshTokenValue();

        RefreshTokenEntity refreshTokenEntity = RefreshTokenEntity.builder()
                .userId(credential.getUserId())
                .tokenHash(jwtService.hashToken(refreshTokenValue))
                .expiresAt(LocalDateTime.now(clock).plusSeconds(jwtProperties.getRefreshTokenExpirationMs() / 1000))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return AuthMapper.toAuthResponseDto(
                accessToken,
                refreshTokenValue,
                jwtProperties.getAccessTokenExpirationMs() / 1000
        );
    }

    @Transactional
    public int revokeAll(Long userId) {
        return refreshTokenRepository.revokeAllByUserId(userId);
    }
}
