package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.PswResetAndOTPRequestBody;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.RequestSMSOTPBody;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.PasswordResetOTPService;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("api/v2/auth")
public class PasswordResetController {

    private final PasswordResetOTPService passwordResetOTPService;

    @PostMapping("/psw-request-otp")
    public ResponseEntity<GlobalJsonResponseBody> requestOTP(@Valid @RequestBody RequestSMSOTPBody requestOTPBody) throws UserExistException, RandomExceptions, JsonProcessingException {
        return new ResponseEntity<>(passwordResetOTPService.generateAndSendPSWDResetOTP(requestOTPBody.getEmail()), HttpStatus.OK);
    }

    @PostMapping("/verify-otp-and-reset")
    public ResponseEntity<GlobalJsonResponseBody> verifyOTP(@Valid @RequestBody PswResetAndOTPRequestBody pswResetAndOTPRequestBody) throws UserExistException, VerificationException, RandomExceptions {
        return new ResponseEntity<>(passwordResetOTPService.verifyOTPAndResetPassword(pswResetAndOTPRequestBody.getEmail(), pswResetAndOTPRequestBody.getCode(), pswResetAndOTPRequestBody.getNewPassword()), HttpStatus.CREATED);
    }

}
