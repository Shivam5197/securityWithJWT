package com.JWT.JsonSecurityToken.repo;

import com.JWT.JsonSecurityToken.Modals.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<UserRole, Long> {
    UserRole findByroleName(String roleName);
}
