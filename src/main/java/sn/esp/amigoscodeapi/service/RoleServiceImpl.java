package sn.esp.amigoscodeapi.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sn.esp.amigoscodeapi.entity.Role;
import sn.esp.amigoscodeapi.repo.RoleRepo;
import sn.esp.amigoscodeapi.service.interfaces.RoleService;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class RoleServiceImpl implements RoleService {
    private final RoleRepo roleRepo;

    @Override
    public Role addRole(Role role) {
        // Add role to database
        return roleRepo.save(role);
    }
}
