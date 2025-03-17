package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service;


import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;

public interface EmailOTPService {
    void generateAndSendEmailOTP(GlobeUserEntity userAuthEntity, String emailHeader, String instructionText) throws RandomExceptions;
    GlobalJsonResponseBody verifyEmailOTP(String email, String otpCode) throws RandomExceptions, VerificationException;
}
