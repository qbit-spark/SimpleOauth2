package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository;

import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.PasswordResetOTPEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PasswordResetOTPRepo extends JpaRepository<PasswordResetOTPEntity, UUID> {
PasswordResetOTPEntity findPasswordResetOTPEntitiesByUser(GlobeUserEntity globeUserEntity);
}
