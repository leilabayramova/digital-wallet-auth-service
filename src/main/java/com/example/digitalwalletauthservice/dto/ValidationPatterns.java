package com.example.digitalwalletauthservice.dto;

public final class ValidationPatterns {

    /** At least one letter and one digit. */
    public static final String PASSWORD = "^(?=.*[A-Za-z])(?=.*\\d).+$";

    public static final String PASSWORD_MESSAGE = "Password must contain at least one letter and one digit";

    private ValidationPatterns() {
    }
}
