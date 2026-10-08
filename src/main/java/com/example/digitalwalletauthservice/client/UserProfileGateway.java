package com.example.digitalwalletauthservice.client;

import com.example.digitalwalletauthservice.dto.CreateUserRequestDto;
import com.example.digitalwalletauthservice.dto.UserProfileResponseDto;
import com.example.digitalwalletauthservice.exception.UserServiceRejectedException;
import com.example.digitalwalletauthservice.exception.UserServiceUnavailableException;
import feign.FeignException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserProfileGateway {

    private final UserServiceClient userServiceClient;

    /** Deterministic per email, so retrying a half-finished registration reuses the same remote profile. */
    public static String idempotencyKeyFor(String normalizedEmail) {
        return UUID.nameUUIDFromBytes(normalizedEmail.getBytes(StandardCharsets.UTF_8)).toString();
    }

    @CircuitBreaker(name = "user-service", fallbackMethod = "createUserFallback")
    public UserProfileResponseDto createUser(CreateUserRequestDto requestDto, String idempotencyKey) {
        try {
            return userServiceClient.createUser(requestDto, idempotencyKey);
        } catch (FeignException.FeignClientException exception) {
            throw new UserServiceRejectedException(exception.status(), "User service rejected the request");
        }
    }

    private UserProfileResponseDto createUserFallback(
            CreateUserRequestDto requestDto, String idempotencyKey, Throwable throwable
    ) {
        if (throwable instanceof UserServiceRejectedException rejected) {
            throw rejected;
        }

        log.error("User-service unavailable. error={}", throwable.getMessage());

        throw new UserServiceUnavailableException("User service is currently unavailable. Please try again later.");
    }
}
