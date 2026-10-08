package com.example.digitalwalletauthservice.client;

import com.example.digitalwalletauthservice.dto.CreateUserRequestDto;
import com.example.digitalwalletauthservice.dto.UserProfileResponseDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "user-service", url = "${clients.user-service.url}")
public interface UserServiceClient {

    @PostMapping("/api/users")
    UserProfileResponseDto createUser(
            @RequestBody CreateUserRequestDto requestDto,
            @RequestHeader("Idempotency-Key") String idempotencyKey
    );
}
