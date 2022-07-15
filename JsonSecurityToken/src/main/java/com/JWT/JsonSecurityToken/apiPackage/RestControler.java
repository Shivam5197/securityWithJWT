package com.JWT.JsonSecurityToken.apiPackage;

import com.JWT.JsonSecurityToken.Modals.AppUsers;
import com.JWT.JsonSecurityToken.Modals.UserRole;
import com.JWT.JsonSecurityToken.service.UserService;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@RequestMapping(value = "/home")
@NoArgsConstructor
@Slf4j
public class RestControler {

    @Autowired
    private UserService userService;

    @GetMapping(value = "/listOfUsers")
    public ResponseEntity<List<AppUsers>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @GetMapping(value="/listOfManager")
    public ResponseEntity<List<AppUsers>> getManagers(){
        return ResponseEntity.ok().body(userService.getManagers());
    }



    @PostMapping(value = "/user/save")
    public ResponseEntity<AppUsers> saveUser(@RequestBody AppUsers user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/home/user/save").toUriString());
        log.info("URI AT the USER SAVE : : " + uri);
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }




    @PostMapping(value = "/role/save")
    public ResponseEntity<UserRole> saveRole(@RequestBody UserRole role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/home/role/save").toUriString());
        log.info("URI AT the Role SAVE : : " + uri);
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping(value = "/role/addToUser")
    public ResponseEntity<?> addRoleToUser(RoleToUserForm form) {
        userService.addRoleToUser(form.getUserName(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/findUser/{userName}")
    public ResponseEntity<AppUsers> getUser(@PathVariable("userName") String userName){
        log.info("Value came to check is :" + userName);
        return ResponseEntity.ok().body(userService.getUser(userName));
    }


    @GetMapping(value = "/refreshToken")
    public void reFreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_Token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("Secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_Token);
                String userName = decodedJWT.getSubject();
                AppUsers user = userService.getUser(userName);

                String access_token = JWT.create()
                        .withSubject(user.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getUserRole().stream().map(UserRole::getRoleName).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception e) {
                e.printStackTrace();
                log.error("Error in do Filter :" + e.getMessage());
                response.setHeader("Error !! ", e.getMessage());
                response.setStatus(HttpURLConnection.HTTP_FORBIDDEN);
                Map<String, String> error = new HashMap<>();
                error.put("error_Message", e.getMessage());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh Token is missing !!");
        }
    }


}

@Data
class RoleToUserForm {
    private String userName;
    private String roleName;
}
