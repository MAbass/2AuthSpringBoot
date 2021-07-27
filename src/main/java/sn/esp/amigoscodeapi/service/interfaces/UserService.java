package sn.esp.amigoscodeapi.service.interfaces;

import sn.esp.amigoscodeapi.entity.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    User getUser(String username);
    User addRoleToUser(String username, String roleName);
    List<User> getUsers();
}
