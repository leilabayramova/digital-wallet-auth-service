package com.example.digitalwalletauthservice.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CreateUserRequestDto {

    private String fullName;
    private String email;
}
