package com.example.digitalwalletauthservice.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateEnabledRequestDto {

    @NotNull(message = "Enabled flag cannot be empty")
    private Boolean enabled;
}
