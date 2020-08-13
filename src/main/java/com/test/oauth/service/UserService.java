package com.test.oauth.service;

import com.test.oauth.entities.UserSecurityEntity;
import com.test.oauth.repository.UserSecurityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
public class UserService implements UserDetailsService, IUserService {

    @Autowired
    private UserSecurityRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserSecurityEntity user = repository.findByEmail(username).orElseThrow(() -> new RuntimeException("User not found: " + username));
        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRol());
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true, true, true, true, Arrays.asList(authority));
    }

    @Override
    public UserSecurityEntity save(UserSecurityEntity userSecurityEntity) {
        String passwordHash = passwordEncoder.encode(userSecurityEntity.getPassword());
        userSecurityEntity.setPassword(passwordHash);
        return repository.save(userSecurityEntity);
    }

    @Override
    public List<UserSecurityEntity> getAll() {
        List<UserSecurityEntity> result = new ArrayList<>();
        Iterable<UserSecurityEntity> iterable = this.repository.findAll();
        for (UserSecurityEntity user : iterable) {
            result.add(user);
        }
        return result;
    }

    @Override
    public UserSecurityEntity getByEmail(String email) {
        Optional<UserSecurityEntity> optional = this.repository.findByEmail(email);
        return optional.orElse(null);
    }
}
