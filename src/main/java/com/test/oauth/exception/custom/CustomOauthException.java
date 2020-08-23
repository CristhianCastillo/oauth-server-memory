package com.test.oauth.exception.custom;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * Custom exception to encapsulate the exceptions thrown by OAuth2.
 *
 * @author cristhian.castillo@ptesa.com
 */
@Getter
@JsonSerialize(using = CustomOauthExceptionSerializer.class)
public class CustomOauthException extends OAuth2Exception {

    /**
     * Default message according to the recommendation of: Enumeration of login error messages credential.
     * The service should return the same authentication error
     */
    public static final String OAUTH_ERROR_AUTHENTICATION = "Username and/or password are not valid.";

    public HttpStatus httpStatus;

    public CustomOauthException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }
}
