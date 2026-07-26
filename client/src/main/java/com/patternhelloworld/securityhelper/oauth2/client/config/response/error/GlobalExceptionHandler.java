package com.patternhelloworld.securityhelper.oauth2.client.config.response.error;


import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.util.ExceptionEasyPlusUtils;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.dto.SecurityEasyPlusErrorResponsePayload;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.response.error.exception.EasyPlusOauth2AuthenticationException;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternhelloworld.securityhelper.oauth2.api.config.util.EasyPlusOrderConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import org.springframework.web.context.request.WebRequest;


/*
 *
 *   Customize the exception payload by implementing this, which replaces
 *          'handler.error.response.security.config.io.github.patternhelloworld.securityhelper.oauth2.api.SecurityEasyPlusExceptionHandler'
 *
 *   Once you create 'GlobalExceptionHandler', you should insert the following two (authenticationException, authorizationException)  as default. Otherwise, 'unhandledExceptionHandler' is prior to 'handler.error.response.security.config.io.github.patternhelloworld.securityhelper.oauth2.api.SecurityEasyPlusExceptionHandler'.
 *   "OrderConstants.SECURITY_EASY_PLUS_EXCEPTION_HANDLER_ORDER - 1" means this is prior to "SecurityEasyPlusExceptionHandler"
 * */
@Order(EasyPlusOrderConstants.SECURITY_EASY_PLUS_EXCEPTION_HANDLER_ORDER - 1)
@ControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    // 401 : Authentication
    @ExceptionHandler({AuthenticationException.class})
    public ResponseEntity<?> authenticationException(Exception ex, WebRequest request) {
        SecurityEasyPlusErrorResponsePayload errorResponsePayload;
        if(ex instanceof EasyPlusOauth2AuthenticationException && ((EasyPlusOauth2AuthenticationException) ex).getErrorMessages() != null) {
            errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(((EasyPlusOauth2AuthenticationException) ex).getErrorMessages(),
                    ex, request.getDescription(false), ExceptionEasyPlusUtils.getAllStackTraces(ex),
                    ExceptionEasyPlusUtils.getAllCauses(ex), null);
        }else {
            errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(ExceptionEasyPlusUtils.getAllCauses(ex), request.getDescription(false), iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_LOGIN_FAILURE),
                    ex.getMessage(), ex.getStackTrace()[0].toString());
        }
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.UNAUTHORIZED);
    }

    // 403 : Authorization
    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<?> authorizationException(Exception ex, WebRequest request) {
        SecurityEasyPlusErrorResponsePayload errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(ex.getMessage() != null ? ex.getMessage() : ExceptionEasyPlusUtils.getAllCauses(ex), request.getDescription(false),
                ex.getMessage() == null || ex.getMessage().equals("Access Denied") ? iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHORIZATION_FAILURE) : ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.FORBIDDEN);
    }

    // Unhandled
/*    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unhandledExceptionHandler(Exception ex, WebRequest request) {
        SecurityEasyPlusErrorResponsePayload errorResponsePayload = new SecurityEasyPlusErrorResponsePayload(ex.getMessage(), request.getDescription(false), GeneralErrorMessage.UNHANDLED_ERROR.getUserMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorResponsePayload, HttpStatus.INTERNAL_SERVER_ERROR);
    }*/

}
