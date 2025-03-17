package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;


public interface PasswordResetOTPService {
    GlobalJsonResponseBody generateAndSendPSWDResetOTP(String email) throws UserExistException, RandomExceptions, JsonProcessingException;
    GlobalJsonResponseBody verifyOTPAndResetPassword(String email, String otpCode, String newPassword) throws UserExistException, RandomExceptions, VerificationException;

}
