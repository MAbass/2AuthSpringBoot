package sn.esp.amigoscodeapi.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sn.esp.amigoscodeapi.entity.Role;
import sn.esp.amigoscodeapi.entity.User;
import sn.esp.amigoscodeapi.repo.RoleRepo;
import sn.esp.amigoscodeapi.repo.UserRepo;
import sn.esp.amigoscodeapi.service.interfaces.UserService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if (user == null) {
            log.error("User {} not found in the database", username);
            throw new UsernameNotFoundException("The user does not exits");
        } else {
            log.info("User {} is found in the database", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoleCollection().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new User in the database");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching User {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public User addRoleToUser(String username, String roleName) {
        log.info("Try to add role {} for user {} ", roleName, username);
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoleCollection().add(role);
        return userRepo.save(user);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all Users");
        return userRepo.findAll();
    }

}
