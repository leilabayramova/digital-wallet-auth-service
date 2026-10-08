package com.example.digitalwalletauthservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshRequestDto {

    @NotBlank(message = "Refresh token cannot be empty")
    private String refreshToken;
}
