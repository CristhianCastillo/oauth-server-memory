package com.test.oauth.service;

import com.test.oauth.entities.UserSecurityEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface IUserService {

    UserSecurityEntity save(UserSecurityEntity userSecurityEntity);

    UserSecurityEntity getByEmail(String email);

    List<UserSecurityEntity> getAll();
}
