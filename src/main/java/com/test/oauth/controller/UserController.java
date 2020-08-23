package com.test.oauth.controller;

import com.test.oauth.entities.UserSecurityEntity;
import com.test.oauth.service.IUserService;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private IUserService iUserService;

    @Autowired
    private ConsumerTokenServices consumerTokenServices;

    // No secure.
    @PostMapping("/api/users/create")
    public Map createUser(@RequestBody UserSecurityEntity userSecurityEntity) {
        UserSecurityEntity newUserCreated = this.iUserService.save(userSecurityEntity);
        Map<String, Object> result = new HashMap<>();
        result.put("user", newUserCreated);
        return result;
    }

    // No secure.
    @PostMapping(path = "/security/oauth/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public @ResponseBody
    ResponseEntity<?> oauthUser(@RequestBody MultiValueMap<String, String> paramMap) {
        if (!paramMap.containsKey("username")) {
            return new ResponseEntity("", HttpStatus.UNAUTHORIZED);
        }

        if (!paramMap.containsKey("password")) {
            return new ResponseEntity("", HttpStatus.UNAUTHORIZED);
        }

        if (!paramMap.containsKey("grant_type")) {
            return new ResponseEntity("", HttpStatus.UNAUTHORIZED);
        }

        String auth = "test-app:12345";
        byte[] encodeAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
        String authValue = "Basic " + new String(encodeAuth);

        RestTemplate restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add(HttpHeaders.AUTHORIZATION, authValue);

        MultiValueMap<String, String> bodyRequest = new LinkedMultiValueMap<>();
        bodyRequest.add("username", paramMap.getFirst("username").toString());
        bodyRequest.add("password", paramMap.getFirst("password").toString());
        bodyRequest.add("grant_type", paramMap.getFirst("grant_type").toString());

        HttpEntity<?> entity = new HttpEntity<>(bodyRequest, headers);

        try {
            ResponseEntity<?> response = restTemplate.exchange("http://localhost:8080/oauth/token", HttpMethod.POST, entity, HashMap.class);
            return response;
        } catch (HttpStatusCodeException e) {
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                return new ResponseEntity<>(e.getResponseBodyAsString(), HttpStatus.UNAUTHORIZED);
            } else {
                return new ResponseEntity("", HttpStatus.UNAUTHORIZED);
            }
        } catch (RestClientException e) {
            return new ResponseEntity("", HttpStatus.UNAUTHORIZED);
        }
    }

    // Secure.
    @GetMapping("/api/users/get/all")
    public List<UserSecurityEntity> getAllUsers() {
        return this.iUserService.getAll();
    }

    /**
     * For Invalidate Token
     *
     * @param httpServletRequest
     * @return
     */
    @DeleteMapping(value = "/api/users/logout")
    public ResponseEntity<?> logout(HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader("Authorization");
        if (authHeader != null) {
            String tokenValue = authHeader.replace("Bearer", "").trim();
            this.consumerTokenServices.revokeToken(tokenValue);
            return new ResponseEntity<>("Logout OK!!", HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Logout BAD!!", HttpStatus.BAD_REQUEST);
        }
    }

}
