package com.example.digitalwalletauthservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerifyEmailRequestDto {

    @NotBlank(message = "Token cannot be empty")
    private String token;
}
