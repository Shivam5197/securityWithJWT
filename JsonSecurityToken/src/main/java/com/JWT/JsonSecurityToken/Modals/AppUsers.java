package com.JWT.JsonSecurityToken.Modals;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

@Entity @Data @AllArgsConstructor @NoArgsConstructor
public class AppUsers {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long userId;
    private String fullName;
    private String userName;
    private String email;
    private String password;
    private Integer gender;

    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<UserRole> userRole = new ArrayList<>();

}
