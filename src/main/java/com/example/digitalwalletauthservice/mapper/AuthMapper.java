package com.example.digitalwalletauthservice.mapper;

import com.example.digitalwalletauthservice.dto.AuthResponseDto;
import com.example.digitalwalletauthservice.dto.UserInfoResponseDto;
import com.example.digitalwalletauthservice.entity.CredentialEntity;
import com.example.digitalwalletauthservice.security.JwtUserPrincipal;

public interface AuthMapper {

    static UserInfoResponseDto toUserInfoResponseDto(CredentialEntity credentialEntity) {
        return UserInfoResponseDto.builder()
                .userId(credentialEntity.getUserId())
                .email(credentialEntity.getEmail())
                .role(credentialEntity.getRole())
                .build();
    }

    static UserInfoResponseDto toUserInfoResponseDto(JwtUserPrincipal principal) {
        return UserInfoResponseDto.builder()
                .userId(principal.userId())
                .email(principal.email())
                .role(principal.role())
                .build();
    }

    static AuthResponseDto toAuthResponseDto(String accessToken, String refreshToken, long expiresInSeconds) {
        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresInSeconds(expiresInSeconds)
                .build();
    }
}
