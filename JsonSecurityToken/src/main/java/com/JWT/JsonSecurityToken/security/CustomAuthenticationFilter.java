package com.JWT.JsonSecurityToken.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public  CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    log.info("-------------------------------------Start of the attemptAuthentication Method -----------------------------------");
    String userName = request.getParameter("userName");
    String password = request.getParameter("password");
    log.info("UserName Entered : {}",userName ,"Password Entered {}", password);

    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userName,password);
    log.info("-------------------------------------End of the attemptAuthentication Method -----------------------------------");
    return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        // get Principle is returning an Object that is why we have to typecast it so It can return User
        User userLoggedIn = (User)authentication.getPrincipal();
        // This Secret text should not be used in Production it should be some In_Crypted and De_Crypted Text
        Algorithm algorithm = Algorithm.HMAC256("Secret".getBytes());

        String access_token = JWT.create()
                .withSubject(userLoggedIn.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+ 10*60*1000 ))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", userLoggedIn.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(userLoggedIn.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+ 30*60*1000 ))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        Map<String,String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(),tokens);
    }


    //TODO: Add UnsuccessfulAuthentication and lock the system after few Tries

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }

}
