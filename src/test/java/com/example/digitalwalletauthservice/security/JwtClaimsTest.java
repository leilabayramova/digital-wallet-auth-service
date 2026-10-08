package com.example.digitalwalletauthservice.security;

import com.example.digitalwalletauthservice.config.JwtProperties;
import com.example.digitalwalletauthservice.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtClaimsTest {

    private static final String SECRET = "test-secret-key-at-least-32-bytes-long";

    private JwtProperties properties;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setAccessTokenExpirationMs(900000);
        properties.setRefreshTokenExpirationMs(604800000);

        jwtService = new JwtService(properties);
    }

    private String tokenWith(String issuer, String audience) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

        var builder = Jwts.builder()
                .subject("1")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(key);

        if (issuer != null) {
            builder.issuer(issuer);
        }
        if (audience != null) {
            builder.audience().add(audience);
        }

        return builder.compact();
    }

    @Test
    void generateAccessToken_shouldContainIssuerAudienceAndUniqueJti() {
        Claims first = jwtService.parseAccessToken(jwtService.generateAccessToken(1L, "leila@example.com", Role.USER));
        Claims second = jwtService.parseAccessToken(jwtService.generateAccessToken(1L, "leila@example.com", Role.USER));

        assertThat(first.getIssuer()).isEqualTo("digital-wallet-auth-service");
        assertThat(first.getAudience()).containsExactly("digital-wallet");
        assertThat(first.getId()).isNotBlank().isNotEqualTo(second.getId());
    }

    @Test
    void parseAccessToken_shouldReject_whenIssuerIsWrong() {
        String token = tokenWith("someone-else", "digital-wallet");

        assertThatThrownBy(() -> jwtService.parseAccessToken(token)).isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    void parseAccessToken_shouldReject_whenAudienceIsMissing() {
        String token = tokenWith("digital-wallet-auth-service", null);

        assertThatThrownBy(() -> jwtService.parseAccessToken(token)).isInstanceOf(MissingClaimException.class);
    }

    @Test
    void properties_shouldBeInvalid_whenSecretIsBlank() {
        properties.setSecret("");

        Set<ConstraintViolation<JwtProperties>> violations = validator().validate(properties);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void properties_shouldBeInvalid_whenSecretIsTooShort() {
        properties.setSecret("too-short");

        Set<ConstraintViolation<JwtProperties>> violations = validator().validate(properties);

        assertThat(violations).extracting(ConstraintViolation::getMessage)
                .contains("jwt.secret must be at least 32 characters long");
    }

    @Test
    void properties_shouldBeValid_whenSecretIsLongEnough() {
        assertThat(validator().validate(properties)).isEmpty();
    }

    private Validator validator() {
        return Validation.buildDefaultValidatorFactory().getValidator();
    }
}
