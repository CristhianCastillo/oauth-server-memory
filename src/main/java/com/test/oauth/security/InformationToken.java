package com.test.oauth.security;

import com.test.oauth.entities.UserSecurityEntity;
import com.test.oauth.service.IUserService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Component
public class InformationToken implements TokenEnhancer {

    private static final Logger log = LogManager.getLogger(InformationToken.class);

    @Autowired
    private IUserService iUserService;

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
                                     OAuth2Authentication authentication) {
        log.info("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis()
                + " - Adding Information Token " + authentication.getName());
        Map<String, Object> additionalInformation = new HashMap<String, Object>();
        UserSecurityEntity userDto = iUserService.getByEmail(authentication.getName());
        additionalInformation.put("user", userDto);
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
        return accessToken;
    }
}
