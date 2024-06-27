package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;

import org.springframework.security.core.userdetails.UsernameNotFoundException;


public class UserDeletedException extends UsernameNotFoundException {
    public UserDeletedException(String message) {
        super(message);
    }
}