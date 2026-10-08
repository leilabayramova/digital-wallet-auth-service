package com.example.digitalwalletauthservice.exception;

import lombok.Getter;

@Getter
public class UserServiceRejectedException extends RuntimeException {

    private final int upstreamStatus;

    public UserServiceRejectedException(int upstreamStatus, String message) {
        super(message);
        this.upstreamStatus = upstreamStatus;
    }
}
