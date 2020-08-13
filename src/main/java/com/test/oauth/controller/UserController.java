package com.test.oauth.controller;

import com.test.oauth.entities.UserSecurityEntity;
import com.test.oauth.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
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

    // Secure.
    @GetMapping("/api/users/get/all")
    public List<UserSecurityEntity> getAllUsers() {
        return this.iUserService.getAll();
    }

    /**
     * For Invalidate Token
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
