package com.example.digitalwalletauthservice.security;

import com.example.digitalwalletauthservice.config.JwtProperties;
import com.example.digitalwalletauthservice.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private JwtProperties jwtProperties;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtProperties = new JwtProperties();
        jwtProperties.setSecret("test-secret-key-at-least-32-bytes-long");
        jwtProperties.setAccessTokenExpirationMs(900000);
        jwtProperties.setRefreshTokenExpirationMs(604800000);

        jwtService = new JwtService(jwtProperties);
    }

    @Test
    void generateAccessToken_shouldProduceToken_thatParseAccessTokenCanDecode() {
        String token = jwtService.generateAccessToken(1L, "john.doe@example.com", Role.USER);

        Claims claims = jwtService.parseAccessToken(token);

        assertThat(claims.getSubject()).isEqualTo("1");
        assertThat(claims.get("email", String.class)).isEqualTo("john.doe@example.com");
        assertThat(claims.get("role", String.class)).isEqualTo("USER");
    }

    @Test
    void parseAccessToken_shouldThrow_whenTokenIsExpired() {
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));

        String expiredToken = Jwts.builder()
                .subject("1")
                .issuedAt(new Date(System.currentTimeMillis() - 10000))
                .expiration(new Date(System.currentTimeMillis() - 5000))
                .signWith(key)
                .compact();

        assertThatThrownBy(() -> jwtService.parseAccessToken(expiredToken))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void parseAccessToken_shouldThrow_whenSignatureIsInvalid() {
        String token = jwtService.generateAccessToken(1L, "john.doe@example.com", Role.USER);

        JwtProperties otherProperties = new JwtProperties();
        otherProperties.setSecret("a-completely-different-secret-key-32-bytes");
        JwtService otherJwtService = new JwtService(otherProperties);

        assertThatThrownBy(() -> otherJwtService.parseAccessToken(token))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    void generateRefreshTokenValue_shouldReturnUniqueValuesOfSufficientLength() {
        String first = jwtService.generateRefreshTokenValue();
        String second = jwtService.generateRefreshTokenValue();

        assertThat(first).isNotEqualTo(second);
        assertThat(first.length()).isGreaterThanOrEqualTo(32);
    }

    @Test
    void hashToken_shouldBeDeterministicHex64Chars() {
        String hash1 = jwtService.hashToken("raw-refresh-token");
        String hash2 = jwtService.hashToken("raw-refresh-token");

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64);
    }

    @Test
    void hashToken_shouldDiffer_forDifferentInputs() {
        String hash1 = jwtService.hashToken("token-a");
        String hash2 = jwtService.hashToken("token-b");

        assertThat(hash1).isNotEqualTo(hash2);
    }
}
