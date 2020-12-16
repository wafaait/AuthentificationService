package org.sid.securiteservice.sec.repositories;

import org.sid.securiteservice.sec.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository  extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
