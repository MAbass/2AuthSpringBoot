package sn.esp.amigoscodeapi.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import sn.esp.amigoscodeapi.entity.User;
@Repository
public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
