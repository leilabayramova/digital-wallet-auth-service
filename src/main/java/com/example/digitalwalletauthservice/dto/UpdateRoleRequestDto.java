package com.example.digitalwalletauthservice.dto;

import com.example.digitalwalletauthservice.entity.Role;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateRoleRequestDto {

    @NotNull(message = "Role cannot be empty")
    private Role role;
}
