package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository;


import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.Roles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;
public interface RolesRepository extends JpaRepository<Roles, UUID> {
    Optional<Roles> findByRoleName(String name);
}
