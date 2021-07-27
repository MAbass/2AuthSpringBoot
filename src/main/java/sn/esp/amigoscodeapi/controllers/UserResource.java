package sn.esp.amigoscodeapi.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import sn.esp.amigoscodeapi.entity.Role;
import sn.esp.amigoscodeapi.entity.User;
import sn.esp.amigoscodeapi.service.interfaces.RoleService;
import sn.esp.amigoscodeapi.service.interfaces.UserService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserResource {

    private final UserService userService;
    private final RoleService roleService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        List<User> users = new ArrayList<>();
        try {
            users = userService.getUsers();

        } catch (NullPointerException exception) {
            log.error("Exception message {}", exception.getMessage());
        }
        return ResponseEntity.ok().body(users);

    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        log.info("User is {}", user.toString());
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        log.info("Access to path add role");
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(roleService.addRole(role));
    }

    @PostMapping("/user/role")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);

                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoleCollection().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception e) {
                log.error("Error to decode token and message is {}", e.getMessage());
                response.setHeader("error", e.getMessage());
                response.setStatus(HttpStatus.FORBIDDEN.value());
                Map<String, String> errors = new HashMap<>();
                errors.put("error_message", e.getMessage());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), errors);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }

        return null;
    }

}

@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}
