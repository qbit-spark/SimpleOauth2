package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.IMPL;


import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.UserOTP;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.LoginResponse;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.GlobeUserRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.UserOTPRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.EmailOTPService;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import com.kibuti.simplifiedoauth2server.GlobeSecurity.JWTProvider;
import com.kibuti.simplifiedoauth2server.GlobeValidationUtils.CustomValidationUtils;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Random;


@RequiredArgsConstructor
@Service
public class EmailOTPIMPL implements EmailOTPService {

    private final JavaMailSender mailSender;

    private final TemplateEngine templateEngine;
    private final UserOTPRepository otpRepository;
    private final GlobeUserRepository globeUserRepository;
    private final UserOTPRepository userOTPRepository;
    private final CustomValidationUtils validationUtils;
    private final JWTProvider tokenProvider;

    @Value("${spring.mail.username}")
    private String emailSender;

    @Value("${otp.expire_time.minutes}")
    private String OTP_EXPIRE_TIME;


    @Override
    public void generateAndSendEmailOTP(GlobeUserEntity userAuthEntity, String emailHeader, String instructionText) throws RandomExceptions {
        // Find the user by email
        GlobeUserEntity user = globeUserRepository.findByEmail(userAuthEntity.getEmail())
                .orElseThrow(() -> new UserExistException("No such user with the given email"));

        // Check if there’s an existing OTP
        UserOTP existingOTP = otpRepository.findUserOTPByUser(user);

        // Generate a new OTP code
        String newOtpCode = generateOtpCode();

        if (existingOTP == null) {
            // Create a new OTP entry if none exists for the user
            existingOTP = new UserOTP();
            existingOTP.setUser(user);
            existingOTP.setSentTime(LocalDateTime.now());
        }
        // Update OTP details
        existingOTP.setOtpCode(newOtpCode);
        existingOTP.setSentTime(LocalDateTime.now());

        // Save the OTP to the repository
        otpRepository.save(existingOTP);

        // Send the OTP via email
        try {
            // Prepare the context for the Thymeleaf template
            Context context = new Context();
            context.setVariable("userName", "Customer");
            context.setVariable("otpCode", newOtpCode);  // OTP to display in email
            context.setVariable("emailHeader", emailHeader);  // Dynamic email header
            context.setVariable("instructionText", instructionText);  // Dynamic instruction text

            // Process Thymeleaf template to generate HTML content
            String htmlContent = templateEngine.process("verification_email", context);

            // Prepare the email message
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(emailSender, "Kitchen Support");
            helper.setTo(user.getEmail());
            helper.setSubject("Verify your account");
            helper.setText(htmlContent, true);  // Send HTML email

            // Send email
            mailSender.send(message);
        } catch (Exception ex) {
            throw new RandomExceptions("Failed to send verification email to user: " + user.getEmail() + ". " + ex.getMessage());
        }
    }



    @Override
    public GlobalJsonResponseBody verifyEmailOTP(String email, String otpCode) throws UserExistException, RandomExceptions, VerificationException {
        // Find the user by email
        GlobeUserEntity user = globeUserRepository.findByEmail(email)
                .orElseThrow(() -> new UserExistException("No such user with the given email"));

        // Find the OTP associated with the user
        UserOTP existingOTP = userOTPRepository.findUserOTPByUser(user);

        // Check if OTP exists and has not expired
        if (existingOTP != null) {
            LocalDateTime createdTime = existingOTP.getSentTime();
            if (validationUtils.isOTPExpired(createdTime)) {
                throw new RandomExceptions("OTP expired");
            }

            // Check if the provided OTP code matches the stored OTP
            if (existingOTP.getOtpCode().equals(otpCode)) {
                var currentTime = LocalDateTime.now();
                var expirationTime = existingOTP.getSentTime().plusMinutes(Long.parseLong(OTP_EXPIRE_TIME));

                // Make the OTP expire after successful password reset
                LocalDateTime expiration = existingOTP.getSentTime().minusHours(2);
                existingOTP.setSentTime(expiration);

                userOTPRepository.save(existingOTP);

                // Validate OTP expiration
                GlobalJsonResponseBody globalJsonResponseBody = getGlobalJsonResponseBody(user, currentTime, expirationTime, globeUserRepository, tokenProvider);
                if (globalJsonResponseBody != null) return globalJsonResponseBody;
            }
        }

        // If OTP is invalid or doesn't match
        throw new VerificationException("OTP or email provided is incorrect");
    }

    static GlobalJsonResponseBody getGlobalJsonResponseBody(GlobeUserEntity user, LocalDateTime currentTime, LocalDateTime expirationTime, GlobeUserRepository globeUserRepository, JWTProvider tokenProvider) {
        if (currentTime.isBefore(expirationTime)) {
            // Mark the user as verified
            user.setIsVerified(true);
            globeUserRepository.save(user);

            // Generate access and refresh tokens
            Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUserName(), null);
            String accessToken = tokenProvider.generateAccessToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(authentication);

            // Construct the response
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setAccessToken(accessToken);
            loginResponse.setRefreshToken(refreshToken);
            loginResponse.setUserData(user);

            GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
            globalJsonResponseBody.setMessage("OTP validation successful");
            globalJsonResponseBody.setData(loginResponse);
            globalJsonResponseBody.setSuccess(true);
            globalJsonResponseBody.setAction_time(new Date());
            globalJsonResponseBody.setHttpStatus(HttpStatus.OK);

            return globalJsonResponseBody;
        }
        return null;
    }

    private String generateOtpCode() {
        // Generate a random OTP code of 6 digits
        Random random = new Random();
        int otp = random.nextInt(900000) + 100000;
        return String.valueOf(otp);
    }
}
