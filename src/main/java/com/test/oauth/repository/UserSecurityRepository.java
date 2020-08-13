package com.test.oauth.repository;

import com.test.oauth.entities.UserSecurityEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSecurityRepository extends CrudRepository<UserSecurityEntity, Long> {
    
    Optional<UserSecurityEntity> findByEmail(String email);

}
