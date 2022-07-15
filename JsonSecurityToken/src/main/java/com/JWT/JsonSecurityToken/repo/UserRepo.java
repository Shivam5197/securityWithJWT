package com.JWT.JsonSecurityToken.repo;

import com.JWT.JsonSecurityToken.Modals.AppUsers;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface UserRepo extends JpaRepository<AppUsers, Long> {

    AppUsers findByUserName(String userName);

//    @Query("Select a from AppUsers")
    List<AppUsers> findByUserRoleRoleId(Long id);
}
