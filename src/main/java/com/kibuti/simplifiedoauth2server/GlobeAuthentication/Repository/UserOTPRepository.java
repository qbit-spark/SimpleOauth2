package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository;


import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.UserOTP;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserOTPRepository extends JpaRepository<UserOTP, Long> {
    UserOTP findUserOTPByUser(GlobeUserEntity userManger);
}
