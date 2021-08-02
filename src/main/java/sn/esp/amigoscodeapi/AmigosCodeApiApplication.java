package sn.esp.amigoscodeapi;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import sn.esp.amigoscodeapi.entity.Role;
import sn.esp.amigoscodeapi.entity.User;
import sn.esp.amigoscodeapi.service.RoleServiceImpl;
import sn.esp.amigoscodeapi.service.UserServiceImpl;

import java.util.ArrayList;

@SpringBootApplication
public class AmigosCodeApiApplication{

    public static void main(String[] args) {
        SpringApplication.run(AmigosCodeApiApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner run(UserServiceImpl userService, RoleServiceImpl roleService){
        return args -> {
            roleService.addRole(new Role(null, "ROLE_USER"));
            roleService.addRole(new Role(null, "ROLE_ADMIN"));
            roleService.addRole(new Role(null, "ROLE_SUPER_ADMIN"));
            roleService.addRole(new Role(null, "ROLE_MANAGER"));

            userService.saveUser(new User(null, "Abass Diallo", "abass", "mypassword", new ArrayList<>()));
            userService.saveUser(new User(null, "Moussa Diallo", "moussa", "mypassword", new ArrayList<>()));
            userService.saveUser(new User(null, "Mama Niang", "mama", "mypassword", new ArrayList<>()));
            userService.saveUser(new User(null, "Mamadou Diallo", "mamadou", "mypassword", new ArrayList<>()));

            userService.addRoleToUser("abass", "ROLE_USER");
            userService.addRoleToUser("moussa", "ROLE_ADMIN");
            userService.addRoleToUser("abass", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("mamadou", "ROLE_MANAGER");
            userService.addRoleToUser("mama", "ROLE_USER");
            userService.addRoleToUser("moussa", "ROLE_USER");
        };
    }
}
