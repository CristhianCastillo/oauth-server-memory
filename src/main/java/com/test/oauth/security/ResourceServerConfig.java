package com.test.oauth.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private static final Logger log = LogManager.getLogger(ResourceServerConfig.class);
    public final static String ALL_RESOURCES = "/**";

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Autowired
    private JwtTokenStore jwtTokenStore;

    @Autowired
    private InMemoryTokenStore tokenStores;

    private List<String> allowedOrigins = new ArrayList() {{
        add("*");
    }};

    private List<String> allowedHeaders = new ArrayList() {{
        add("*");
    }};

//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) {
//        resources.resourceId("api");
//    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(jwtTokenStore);
        resources.resourceId("resource").tokenStore(tokenStores); // For save token in memory.
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/oauth/**", "/api/users/create").permitAll();
        http.authorizeRequests().anyRequest().authenticated().and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .cors().configurationSource(corsConfigurationSource());

//        http
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .antMatcher("/api/**")
//                .authorizeRequests()
//                .antMatchers("/api/users/create").permitAll()
//                .antMatchers("/oauth/token").permitAll()
////                .antMatchers("/api/glee**").hasAnyAuthority("ADMIN", "USER")
////                .antMatchers("/api/users**").hasAuthority("ADMIN")
////                .antMatchers("/api/users/get/all").hasAuthority("PROGRAMMER")
//                .antMatchers("/api/**").authenticated()
//                .anyRequest().authenticated()
//                .and()
//                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        log.info("Allowed origins, angular app domain {}", this.allowedOrigins);
        List<String> origins = this.allowedOrigins;
        List<String> headers = buildAllowedHeaders();

        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(origins);
        corsConfig.setAllowedMethods(
                Arrays.asList(HttpMethod.OPTIONS.name(), HttpMethod.GET.name(), HttpMethod.POST.name(),
                        HttpMethod.PUT.name(), HttpMethod.DELETE.name()));
        corsConfig.setAllowedHeaders(headers);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(ALL_RESOURCES, corsConfig);

        return source;
    }

    private List<String> buildAllowedHeaders() {
        List<String> headers = new ArrayList<>();
        headers.addAll(
                Arrays.asList(HttpHeaders.ACCEPT, HttpHeaders.ACCEPT_ENCODING, HttpHeaders.ACCEPT_LANGUAGE,
                        HttpHeaders.CACHE_CONTROL, HttpHeaders.CONNECTION, HttpHeaders.CONTENT_LENGTH,
                        HttpHeaders.CONTENT_TYPE, HttpHeaders.HOST, HttpHeaders.ORIGIN, HttpHeaders.PRAGMA,
                        HttpHeaders.REFERER, HttpHeaders.USER_AGENT, HttpHeaders.AUTHORIZATION));

        if (!StringUtils.isEmpty(this.allowedHeaders)) {
            headers.addAll(this.allowedHeaders);
        }
        log.info("Allowed headers, angular app domain {}", headers);
        return headers;
    }

}