package com.example.digitalwalletauthservice.repository;

import com.example.digitalwalletauthservice.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    @Modifying
    @Query("update RefreshTokenEntity t set t.revoked = true "
            + "where t.id = :id and t.revoked = false and t.expiresAt > :now")
    int revokeIfUsable(@Param("id") Long id, @Param("now") LocalDateTime now);

    @Modifying
    @Query("update RefreshTokenEntity t set t.revoked = true where t.userId = :userId and t.revoked = false")
    int revokeAllByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("delete from RefreshTokenEntity t where t.expiresAt < :cutoff or (t.revoked = true and t.createdAt < :cutoff)")
    int deleteStale(@Param("cutoff") LocalDateTime cutoff);
}
