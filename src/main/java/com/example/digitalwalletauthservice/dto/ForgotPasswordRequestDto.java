package com.example.digitalwalletauthservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ForgotPasswordRequestDto {

    @NotBlank(message = "Email cannot be empty")
    @Email(message = "Email format is invalid")
    private String email;
}
