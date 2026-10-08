package com.example.digitalwalletauthservice.service;

import com.example.digitalwalletauthservice.config.AuthProperties;
import com.example.digitalwalletauthservice.repository.OneTimeTokenRepository;
import com.example.digitalwalletauthservice.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanupJob {

    private final RefreshTokenRepository refreshTokenRepository;
    private final OneTimeTokenRepository oneTimeTokenRepository;
    private final AuthProperties authProperties;
    private final Clock clock;

    @Scheduled(cron = "${auth.cleanup-cron:0 0 3 * * *}")
    @Transactional
    public void purgeStaleTokens() {
        LocalDateTime cutoff = LocalDateTime.now(clock).minusDays(authProperties.getCleanupRetentionDays());

        int refreshTokens = refreshTokenRepository.deleteStale(cutoff);
        int oneTimeTokens = oneTimeTokenRepository.deleteStale(cutoff);

        log.info("Token cleanup finished. refreshTokensDeleted={} oneTimeTokensDeleted={}", refreshTokens, oneTimeTokens);
    }
}
