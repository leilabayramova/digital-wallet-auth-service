package com.example.digitalwalletauthservice.repository;

import com.example.digitalwalletauthservice.entity.OneTimeTokenEntity;
import com.example.digitalwalletauthservice.entity.OneTimeTokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface OneTimeTokenRepository extends JpaRepository<OneTimeTokenEntity, Long> {

    Optional<OneTimeTokenEntity> findByTokenHashAndType(String tokenHash, OneTimeTokenType type);

    @Modifying
    @Query("update OneTimeTokenEntity t set t.used = true "
            + "where t.id = :id and t.used = false and t.expiresAt > :now")
    int markUsedIfValid(@Param("id") Long id, @Param("now") LocalDateTime now);

    @Modifying
    @Query("update OneTimeTokenEntity t set t.used = true "
            + "where t.userId = :userId and t.type = :type and t.used = false")
    int invalidateAllUnused(@Param("userId") Long userId, @Param("type") OneTimeTokenType type);

    @Modifying
    @Query("delete from OneTimeTokenEntity t where t.expiresAt < :cutoff or (t.used = true and t.createdAt < :cutoff)")
    int deleteStale(@Param("cutoff") LocalDateTime cutoff);
}
