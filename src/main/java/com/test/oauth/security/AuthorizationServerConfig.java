package com.test.oauth.security;

import com.test.oauth.security.custom.EnhancedAuthenticationKeyGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;
import java.util.Calendar;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private static final Logger log = LogManager.getLogger(AuthorizationServerConfig.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userService;

    @Autowired
    private InformationToken informationToken;

    @Value("${jwt.clientId:kentaurus}")
    private String clientId;

    @Value("${jwt.client-secret:secret}")
    private String clientSecret;

    @Value("${jwt.accessTokenValidititySeconds:43200}") // 12 hours
    private int accessTokenValiditySeconds;

    @Value("${jwt.authorizedGrantTypes:password,authorization_code,refresh_token}")
    private String[] authorizedGrantTypes;

    @Value("${jwt.refreshTokenValiditySeconds:2592000}") // 30 days
    private int refreshTokenValiditySeconds;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis() + " - Configuring Security Autorization Server");
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis() + " - Configuring Client Details Service");
        InMemoryClientDetailsServiceBuilder builder = clients.inMemory();
        builder.withClient("test-app")
                .secret(passwordEncoder.encode("12345"))
                .scopes("read", "write")
                .authorizedGrantTypes("password", "refresh_token", "IMPLICIT")
                .accessTokenValiditySeconds(43200)
                .refreshTokenValiditySeconds(2592000)
                .and();

//        clients.inMemory()
//                .withClient("test-app")
//                .secret(passwordEncoder.encode("12345"))
//                .accessTokenValiditySeconds(accessTokenValiditySeconds)
//                .refreshTokenValiditySeconds(refreshTokenValiditySeconds)
//                .authorizedGrantTypes("password","refresh_token")
//                .scopes("read", "write");
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis() + " - Configuring Endpoints Autorization Server");
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter(), informationToken));

        endpoints.authenticationManager(authenticationManager)
                .tokenStore(tokenStores()) // For save token in memory
                .accessTokenConverter(accessTokenConverter())
                .userDetailsService(userService)
                .tokenEnhancer(tokenEnhancerChain);
    }

    @Bean
    public JwtTokenStore tokenStore() {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis() + " - Creating Token Store");
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * Save Token in memory
     *
     * @return
     */
    @Bean
    public InMemoryTokenStore tokenStores() {
        InMemoryTokenStore inMemoryTokenStore = new InMemoryTokenStore();
        inMemoryTokenStore.setAuthenticationKeyGenerator(new EnhancedAuthenticationKeyGenerator());
        return inMemoryTokenStore;
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        log.debug("##### OAUTH ##### " + Calendar.getInstance().getTimeInMillis() + " - Creating Access Token Converter");
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("**aze6z9i8d^=d.*GLM4AXh)Hpbg3M]sR4f7cxD!:9e6THrPtp^!AY=&FFUm7kK^");
        return converter;
    }

}