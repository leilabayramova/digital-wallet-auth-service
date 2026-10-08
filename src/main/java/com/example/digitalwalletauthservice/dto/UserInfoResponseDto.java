package com.example.digitalwalletauthservice.dto;

import com.example.digitalwalletauthservice.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class UserInfoResponseDto {

    private Long userId;
    private String email;
    private Role role;
}
