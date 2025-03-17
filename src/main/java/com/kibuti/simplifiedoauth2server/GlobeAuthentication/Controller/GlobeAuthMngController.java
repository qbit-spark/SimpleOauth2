package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.TokenInvalidException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.VerificationException;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.RefreshTokenDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserLoginDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserRegisterDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.PasswordResetOTPService;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.UserManagementService;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@AllArgsConstructor
@RestController
@RequestMapping("api/v2/auth")
public class GlobeAuthMngController {

    private final UserManagementService userManagementService;
    private final PasswordResetOTPService passwordResetOTPService;

    @PostMapping("/register")
    public ResponseEntity<GlobalJsonResponseBody> userRegistration(@Valid @RequestBody UserRegisterDTO userManagementDTO) throws UserExistException, RandomExceptions, JsonProcessingException {
        return new ResponseEntity<>(userManagementService.registerUser(userManagementDTO), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<GlobalJsonResponseBody> userLogin(@Valid @RequestBody UserLoginDTO userLoginDTO) throws UserExistException, VerificationException {
        return new ResponseEntity<>(userManagementService.loginUser(userLoginDTO), HttpStatus.OK);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<GlobalJsonResponseBody> refreshToken(@Valid @RequestBody RefreshTokenDTO refreshTokenDTO) throws RandomExceptions, TokenInvalidException {
        return new ResponseEntity<>(userManagementService.refreshToken(refreshTokenDTO.getRefreshToken()), HttpStatus.ACCEPTED);
    }



    @GetMapping("/all-users")
    public ResponseEntity<List<GlobalJsonResponseBody>> getAllUsers() {
        return new ResponseEntity<>(userManagementService.getAllUser(), HttpStatus.CREATED);
    }


    @GetMapping("/single-user/{userId}")
    public ResponseEntity<GlobalJsonResponseBody> getSingleUser(@PathVariable UUID userId) throws UserExistException, VerificationException {
        return new ResponseEntity<>(userManagementService.getSingleUser(userId), HttpStatus.OK);
    }


}
