package org.sid.securiteservice.sec.repositories;

import org.sid.securiteservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository  extends JpaRepository<AppUser,Long> {
    AppUser findByUsername(String username);
}
