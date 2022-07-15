package com.JWT.JsonSecurityToken.service;

import com.JWT.JsonSecurityToken.Modals.AppUsers;
import com.JWT.JsonSecurityToken.Modals.UserRole;
import com.JWT.JsonSecurityToken.repo.RoleRepo;
import com.JWT.JsonSecurityToken.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public interface UserService {

    AppUsers saveUser(AppUsers user);
    UserRole saveRole(UserRole role);
    void addRoleToUser(String userName, String roleName);
    AppUsers getUser(String userName);
    List<AppUsers> getUsers();
    List <AppUsers> getManagers();

    @Service
    @RequiredArgsConstructor
    @Transactional
    @Slf4j
    class UserServiceImpl implements UserService, UserDetailsService {
        private final UserRepo userRepo;
        private final RoleRepo roleRepo;
        private  final PasswordEncoder passwordEncoder;

    // This is The Method that is overridden by the UserDetailsService for Security Purposes
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            AppUsers user = userRepo.findByUserName(username);
            if (user ==null){
                log.error("User is not Found in the DataBase !!");
                throw new UsernameNotFoundException("User not found in DataBase !!");
            }else {
                log.info("User found in the DataBase ");
            }
            Collection<SimpleGrantedAuthority> authorites = new ArrayList<>();
            user.getUserRole().forEach(role -> {
                authorites.add(new SimpleGrantedAuthority(role.getRoleName()));
            });

            //import org.springframework.security.core.userdetails.UserDetails.User; this is the Import for this User
            return new User(user.getUserName(),user.getPassword(),authorites);
        }

        @Override
        public AppUsers saveUser(AppUsers user) {
            log.info("Saving new User in the Database !!");
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            log.info("User Password After Encoding the Password : "+user.getPassword());
            return userRepo.save(user);
        }

        @Override
        public UserRole saveRole(UserRole role) {
            log.info("Saving new Role in the Database !! " +role.getRoleName());
            return roleRepo.save(role);
        }

        @Override
        public void addRoleToUser(String userName, String roleName) {
            log.info("Adding a new" +roleName.toUpperCase(Locale.ROOT)+ "Role to User with Username" + userName.toUpperCase(Locale.ROOT));
        AppUsers user = userRepo.findByUserName(userName);
        UserRole role = roleRepo.findByroleName(roleName);
        user.getUserRole().add(role);
        }

        @Override
        public AppUsers getUser(String userName) {
            log.info("Getting the Single USer : "  + userName);
            return userRepo.findByUserName(userName);
        }

        @Override
        public List<AppUsers> getUsers() {
        log.info("Getting the List of Users !!");
            return userRepo.findAll();
        }

        @Override
        public List<AppUsers> getManagers() {
            Long l = 3L;
            log.info("Getting the List of managers ");
            return userRepo.findByUserRoleRoleId(l);
        }



    }
}
