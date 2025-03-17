package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.EmailOTPRequestBody;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.RequestEmailOTPBody;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.GlobeUserRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.EmailOTPService;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RequiredArgsConstructor
@RestController
@RequestMapping("api/v2/auth")
public class OTPController {

    private final GlobeUserRepository globeUserRepository;
    private final EmailOTPService emailOTPService;


    @PostMapping("/request-otp")
    public ResponseEntity<GlobalJsonResponseBody> requestEmailOTP(@Valid @RequestBody RequestEmailOTPBody requestEmailOTPBody) throws UserExistException, RandomExceptions, JsonProcessingException {
        GlobeUserEntity userAuthEntity = globeUserRepository.findByEmail(requestEmailOTPBody.getEmail()).orElseThrow(
                ()->new UserExistException("User with provided email does not exist")
        );

        // Send the OTP via Email for password reset
        String emailHeader = "Welcome to Kitchen Support!";
        String instructionText = "Please use the following OTP to complete your registration:";
        emailOTPService.generateAndSendEmailOTP(userAuthEntity, emailHeader, instructionText);

        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage("New OTP code sent successful");
        globalJsonResponseBody.setData("New OTP code set successful to "+userAuthEntity.getEmail());
        globalJsonResponseBody.setSuccess(true);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(HttpStatus.OK);

        return ResponseEntity.ok(globalJsonResponseBody);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<GlobalJsonResponseBody> verifyEmailOTP(@Valid @RequestBody EmailOTPRequestBody emailOTPRequestBody) throws UserExistException, VerificationException, RandomExceptions {
        return new ResponseEntity<>(emailOTPService.verifyEmailOTP(emailOTPRequestBody.getEmail(), emailOTPRequestBody.getCode()), HttpStatus.OK);
    }
}
