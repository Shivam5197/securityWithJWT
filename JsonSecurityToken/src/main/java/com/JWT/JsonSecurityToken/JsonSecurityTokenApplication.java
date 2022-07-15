package com.JWT.JsonSecurityToken;

import com.JWT.JsonSecurityToken.Modals.AppUsers;
import com.JWT.JsonSecurityToken.Modals.UserRole;
import com.JWT.JsonSecurityToken.Utils.Util;
import com.JWT.JsonSecurityToken.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JsonSecurityTokenApplication {

	public static void main(String[] args) {
		SpringApplication.run(JsonSecurityTokenApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
	    return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
			return args->{
				userService.saveRole(new UserRole(null, Util.ROLES.ROLE_USER));
				userService.saveRole(new UserRole(null, Util.ROLES.ROLE_MANAGER));
				userService.saveRole(new UserRole(null, Util.ROLES.ROLE_STORE_OWNER));
				userService.saveRole(new UserRole(null, Util.ROLES.ROLE_SUPER_ADMIN));
				userService.saveRole(new UserRole(null, Util.ROLES.ROLE_SALE_MANAGER));

				userService.saveUser(new AppUsers(null, "Ramesh Sharma" , "ramesh@72" , "ramesh72@gmail.com" , "shivam5197" , Util.Gender.MALE, new ArrayList<>()));
				userService.saveUser(new AppUsers(null, "Rashmi Sharma" , "rashmi@72" , "rashmi@gmail.com" , "shivam5197" , Util.Gender.FEMALE, new ArrayList<>()));
				userService.saveUser(new AppUsers(null, "Shivam Sharma" , "shivam@5197" , "shivam5197@gmail.com" , "shivam5197" , Util.Gender.MALE, new ArrayList<>()));
				userService.saveUser(new AppUsers(null, "Sakshi Sharma" , "sakshi@72" , "sakshi@gmail.com" , "shivam5197" , Util.Gender.FEMALE, new ArrayList<>()));
				userService.saveUser(new AppUsers(null, "Ankur Sharma" , "ankur@72" , "ankur@gmail.com" , "shivam5197" , Util.Gender.MALE, new ArrayList<>()));

				userService.addRoleToUser("ramesh@72" ,Util.ROLES.ROLE_SUPER_ADMIN);
				userService.addRoleToUser("ramesh@72" ,Util.ROLES.ROLE_MANAGER);
				userService.addRoleToUser("ramesh@72" ,Util.ROLES.ROLE_USER);
				userService.addRoleToUser("rashmi@72" ,Util.ROLES.ROLE_STORE_OWNER);
				userService.addRoleToUser("shivam@5197" ,Util.ROLES.ROLE_SUPER_ADMIN);
				userService.addRoleToUser("shivam@5197" ,Util.ROLES.ROLE_MANAGER);
				userService.addRoleToUser("shivam@5197" ,Util.ROLES.ROLE_STORE_OWNER);
				userService.addRoleToUser("sakshi@72" ,Util.ROLES.ROLE_USER);
				userService.addRoleToUser("ankur@72" , Util.ROLES.ROLE_USER);
				userService.addRoleToUser("ankur@72" , Util.ROLES.ROLE_SALE_MANAGER);
			};
		}
}