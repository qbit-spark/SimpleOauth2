package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.IMPL;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.UserOTP;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.GlobeUserRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.UserOTPRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.EmailOTPService;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.PasswordResetOTPService;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import com.kibuti.simplifiedoauth2server.GlobeValidationUtils.CustomValidationUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Date;

@RequiredArgsConstructor
@Service
public class PasswordResetOTPServiceIMPL implements PasswordResetOTPService {

    @Value("${otp.expire_time.minutes}")
    private String EXPIRE_TIME;

   private final GlobeUserRepository globeUserRepository;
    private final CustomValidationUtils validationUtils;
    private final PasswordEncoder passwordEncoder;
    private final EmailOTPService emailOTPService;
    private final UserOTPRepository userOTPRepository;

    @Override
    public GlobalJsonResponseBody generateAndSendPSWDResetOTP(String email) throws UserExistException, RandomExceptions, JsonProcessingException {

            GlobeUserEntity globeUserEntity = globeUserRepository.findByEmail(email)
                .orElseThrow(()-> new UserExistException("No such user with given email"));

            if (globeUserEntity.getIsVerified().equals(false)){
                throw new RandomExceptions("You need to verify your account first before reset password");
            }


        //Todo: Send the OTP via SMS
        //sendBulkSMS(email, newOtpCode, USERNAME, PASSWORD);

        //Todo: Send the OTP via Email
        String emailHeader = "Password Reset Request";
        String instructionText = "Please use the following OTP to reset your password:";
        emailOTPService.generateAndSendEmailOTP(globeUserEntity, emailHeader, instructionText);

        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage("OTP generated & sent");
        globalJsonResponseBody.setData("OTP sent to " + email);
        globalJsonResponseBody.setSuccess(true);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(HttpStatus.CREATED);

        return globalJsonResponseBody;
    }

    @Override
    public GlobalJsonResponseBody verifyOTPAndResetPassword(String email, String otpCode, String newPassword) throws UserExistException, RandomExceptions, VerificationException {

        // Fetch the user by phone number
        GlobeUserEntity user = globeUserRepository.findByEmail(email)
                .orElseThrow(() -> new UserExistException("No such user with given phone number"));

        UserOTP existingOTP = userOTPRepository.findUserOTPByUser(user);
                if (existingOTP == null) {
            throw new VerificationException("No OTP found for this phone number. Please request a new OTP.");
        }


        // Check if OTP is expired
        LocalDateTime createdTime = existingOTP.getSentTime();
        if (validationUtils.isOTPExpired(createdTime)) {
            throw new RandomExceptions("OTP expired");
        }

        // Verify the OTP code
        if (existingOTP.getOtpCode().equals(otpCode)) {
            LocalDateTime currentTime = LocalDateTime.now();
            LocalDateTime expirationTime = existingOTP.getSentTime().plusMinutes(Long.parseLong(EXPIRE_TIME));

            // Check if OTP is not expired
            if (currentTime.isBefore(expirationTime)) {

                // Reset the password
                user.setPassword(passwordEncoder.encode(newPassword)); // Assuming you have a PasswordEncoder bean
                globeUserRepository.save(user); // Save the new password to the user record

                // Make the OTP expire after successful password reset
                LocalDateTime expiration = existingOTP.getSentTime().minusHours(2);
                existingOTP.setSentTime(expiration);

                userOTPRepository.save(existingOTP);

                // Prepare success response
                GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
                globalJsonResponseBody.setMessage("Password reset successful");
                globalJsonResponseBody.setData("Password reset successful");
                globalJsonResponseBody.setSuccess(true);
                globalJsonResponseBody.setAction_time(new Date());
                globalJsonResponseBody.setHttpStatus(HttpStatus.OK);

                return globalJsonResponseBody;
            }else {
                throw new VerificationException("OTP expired");
            }
        }

        throw new VerificationException("OTP or phone number provided is incorrect");
    }
}
