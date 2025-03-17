package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Repo;

import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Entity.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ClientRepository extends JpaRepository<ClientEntity, UUID> {
    Optional<ClientEntity> findByClientId(String clientId);
    boolean existsByClientId(String clientId);
}