package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

// 인증 (UNAUTHORIZED) : 401
// 승인 (FORBIDDEN) : 403
@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class AlreadySocialRegisteredException extends RuntimeException {
    public AlreadySocialRegisteredException(String message) {
        super(message);
    }
}