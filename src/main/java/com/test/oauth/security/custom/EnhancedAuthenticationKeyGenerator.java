package com.test.oauth.security.custom;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class EnhancedAuthenticationKeyGenerator extends DefaultAuthenticationKeyGenerator {

    public static final String PARAM_CLIENT_INSTANCE_ID = "client_instance_id";

    private static final String KEY_SUPER_KEY = "super_key";
    private static final String KEY_CLIENT_INSTANCE_ID = PARAM_CLIENT_INSTANCE_ID;

    @Override
    public String extractKey(final OAuth2Authentication authentication) {
        final String superKey = super.extractKey(authentication);

        UUID uuid = UUID.randomUUID();

        final OAuth2Request authorizationRequest = authentication.getOAuth2Request();
        final Map<String, String> requestParameters = authorizationRequest.getRequestParameters();

        final String clientInstanceId = requestParameters != null ? requestParameters.get(PARAM_CLIENT_INSTANCE_ID) : null;
        if (clientInstanceId == null || clientInstanceId.length() == 0) {
            return uuid.toString();
        }

        final Map<String, String> values = new LinkedHashMap<>(2);
        values.put(KEY_SUPER_KEY, superKey);
        values.put(KEY_CLIENT_INSTANCE_ID, clientInstanceId);

        return generateKey(values);
    }

}