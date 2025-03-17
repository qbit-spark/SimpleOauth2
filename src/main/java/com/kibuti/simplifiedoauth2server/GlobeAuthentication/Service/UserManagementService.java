package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.TokenInvalidException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserLoginDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserRegisterDTO;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;

import java.util.List;
import java.util.UUID;

public interface UserManagementService {
    GlobalJsonResponseBody registerUser(UserRegisterDTO userManagementDTO) throws UserExistException, RandomExceptions, JsonProcessingException;
    //Login
    GlobalJsonResponseBody loginUser(UserLoginDTO userLoginDTO) throws UserExistException, VerificationException;

    GlobalJsonResponseBody refreshToken(String refreshToken) throws RandomExceptions, TokenInvalidException;

   // GlobalJsonResponseBody oAuthLoginOrRegister(String authorizationCode, String provider) throws Exception;
    //Edit
    //View all
    List<GlobalJsonResponseBody> getAllUser();
    //View single
    GlobalJsonResponseBody getSingleUser(UUID uuid);
    //Approval
    //SetUserAccount
    //Send OTP

    GlobalJsonResponseBody resetPassword(String phoneNumber, String newPassword);
}
