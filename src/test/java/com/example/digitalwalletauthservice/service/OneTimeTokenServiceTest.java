package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.entity.OneTimeTokenEntity;
import com.example.digitalwalletauthservice.entity.OneTimeTokenType;
import com.example.digitalwalletauthservice.exception.InvalidOneTimeTokenException;
import com.example.digitalwalletauthservice.repository.OneTimeTokenRepository;
import com.example.digitalwalletauthservice.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OneTimeTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

    @Mock
    private OneTimeTokenRepository oneTimeTokenRepository;

    @Mock
    private JwtService jwtService;

    private OneTimeTokenService service;

    @BeforeEach
    void setUp() {
        service = new OneTimeTokenService(oneTimeTokenRepository, jwtService, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void issue_shouldInvalidateEarlierTokensAndStoreOnlyTheHash() {
        when(jwtService.generateRefreshTokenValue()).thenReturn("raw-token");
        when(jwtService.hashToken("raw-token")).thenReturn("hashed");

        String result = service.issue(10L, OneTimeTokenType.PASSWORD_RESET, Duration.ofMinutes(30));

        assertThat(result).isEqualTo("raw-token");

        var order = inOrder(oneTimeTokenRepository);
        order.verify(oneTimeTokenRepository).invalidateAllUnused(10L, OneTimeTokenType.PASSWORD_RESET);

        ArgumentCaptor<OneTimeTokenEntity> captor = ArgumentCaptor.forClass(OneTimeTokenEntity.class);
        order.verify(oneTimeTokenRepository).save(captor.capture());

        assertThat(captor.getValue().getTokenHash()).isEqualTo("hashed");
        assertThat(captor.getValue().getUserId()).isEqualTo(10L);
        assertThat(captor.getValue().isUsed()).isFalse();
        assertThat(captor.getValue().getExpiresAt())
                .isEqualTo(LocalDateTime.ofInstant(NOW, ZoneOffset.UTC).plusMinutes(30));
    }

    @Test
    void consume_shouldReturnUserId_whenTokenIsValid() {
        OneTimeTokenEntity token = OneTimeTokenEntity.builder().id(7L).userId(10L).build();

        when(jwtService.hashToken("raw-token")).thenReturn("hashed");
        when(oneTimeTokenRepository.findByTokenHashAndType("hashed", OneTimeTokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(token));
        when(oneTimeTokenRepository.markUsedIfValid(eq(7L), any(LocalDateTime.class))).thenReturn(1);

        assertThat(service.consume("raw-token", OneTimeTokenType.EMAIL_VERIFICATION)).isEqualTo(10L);
    }

    @Test
    void consume_shouldThrow_whenTokenIsUnknown() {
        when(jwtService.hashToken("raw-token")).thenReturn("hashed");
        when(oneTimeTokenRepository.findByTokenHashAndType("hashed", OneTimeTokenType.PASSWORD_RESET))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.consume("raw-token", OneTimeTokenType.PASSWORD_RESET))
                .isInstanceOf(InvalidOneTimeTokenException.class);
    }

    @Test
    void consume_shouldThrow_whenTokenIsExpiredOrAlreadyUsed() {
        OneTimeTokenEntity token = OneTimeTokenEntity.builder().id(7L).userId(10L).build();

        when(jwtService.hashToken("raw-token")).thenReturn("hashed");
        when(oneTimeTokenRepository.findByTokenHashAndType("hashed", OneTimeTokenType.PASSWORD_RESET))
                .thenReturn(Optional.of(token));
        when(oneTimeTokenRepository.markUsedIfValid(eq(7L), any(LocalDateTime.class))).thenReturn(0);

        assertThatThrownBy(() -> service.consume("raw-token", OneTimeTokenType.PASSWORD_RESET))
                .isInstanceOf(InvalidOneTimeTokenException.class);
    }
}
