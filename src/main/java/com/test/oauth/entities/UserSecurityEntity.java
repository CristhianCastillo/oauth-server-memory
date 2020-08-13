package com.test.oauth.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "user")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserSecurityEntity {

    @Id
    @GeneratedValue(generator = "user_sequence_key_id")
    @SequenceGenerator(
            name = "user_sequence_key_id",
            sequenceName = "user_sequence_key_id",
            initialValue = 1
    )
    private Long id;
    @Column(nullable = false, name = "email")
    private String email;
    @Column(nullable = false, name = "user_name")
    private String userName;
    @Column(nullable = false, name = "password")
    private String password;
    @Column(nullable = false, name = "rol")
    private String rol;
}
