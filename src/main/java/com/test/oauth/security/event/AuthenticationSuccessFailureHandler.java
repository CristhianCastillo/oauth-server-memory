package com.test.oauth.security.event;

import com.test.oauth.service.IUserService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Calendar;

@Component
public class AuthenticationSuccessFailureHandler implements AuthenticationEventPublisher {

    private static final Logger log = LogManager.getLogger(AuthenticationSuccessFailureHandler.class);

    @Autowired
    private IUserService userService;

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis()
                + " - Publish Authentication Success " + authentication.getName());
        log.info("Success Login " + authentication.getName());
//        UserAccount user = userService.findByUsername(authentication.getName());

//        if (user.getAttempts() > 0) {
//            user.setAttempts(0);
//            userService.update(user, user.getUserAccountId());
//        }
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException exception,
                                             Authentication authentication) {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis()
                + " - Publish Authentication Failure " + authentication.getName());
        log.info("Error Login " + exception.getMessage());
//        try {
//            UserAccount user = userService.findByUsername(authentication.getName());
//            user.setAttempts(user.getAttempts() + 1);
//
//            if (user.getAttempts() >= 3) {
//                user.setEnabled(false);
//            }
//
//            userService.update(user, user.getUserAccountId());
//
//        } catch (FeignException e) {
//            log.error(
//                    String.format("El usuario %s no existe en el sistema", authentication.getName()));
//        }
    }

}
