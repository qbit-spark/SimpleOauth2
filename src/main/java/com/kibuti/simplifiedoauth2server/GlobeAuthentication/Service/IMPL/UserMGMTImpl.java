package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.IMPL;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.*;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserLoginDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserRegisterDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs.UserRegisterResponseDTO;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.GlobeUserEntity;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity.Roles;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.LoginResponse;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads.RefreshTokenResponse;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.GlobeUserRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Repository.RolesRepository;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.EmailOTPService;
import com.kibuti.simplifiedoauth2server.GlobeAuthentication.Service.UserManagementService;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import com.kibuti.simplifiedoauth2server.GlobeSecurity.JWTProvider;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class UserMGMTImpl implements UserManagementService {

    private final GlobeUserRepository globeUserRepository;
    private final RolesRepository rolesRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTProvider tokenProvider;
    private final EmailOTPService emailOTPService;


    @Override
    public GlobalJsonResponseBody registerUser(UserRegisterDTO userManagementDTO) throws UserExistException, RandomExceptions, JsonProcessingException, RandomExceptions {

        //Todo: check the existence of user
        if (globeUserRepository.existsByPhoneNumberOrEmailOrUserName(userManagementDTO.getPhoneNumber(),
                userManagementDTO.getEmail(),
                userManagementDTO.getUserName())) {
            throw new UserExistException("User with provided credentials already exist, login");
        }

        GlobeUserEntity userManger = convertDTOToEntity(userManagementDTO);
        userManger.setUserName(generateUserName(userManagementDTO.getEmail()));
        userManger.setCreatedAt(new Date());
        userManger.setEditedAt(new Date());
        userManger.setIsVerified(false);
        userManger.setPassword(passwordEncoder.encode(userManagementDTO.getPassword()));
        //Todo: lets set the user role
        Set<Roles> roles = new HashSet<>();
        Roles userRoles = rolesRepository.findByRoleName("ROLE_USER").get();
        roles.add(userRoles);
        userManger.setRoles(roles);
        globeUserRepository.save(userManger);


        //Todo: send OTP or email OTP HERE.....
       // smsotpService.generateAndSendPSWDResetOTP(userManger.getPhoneNumber());

        // Todo: Send the OTP via Email for registration
        String emailHeader = "Welcome to Kitchen Support!";
        String instructionText = "Please use the following OTP to complete your registration:";
        emailOTPService.generateAndSendEmailOTP(userManger, emailHeader, instructionText);


        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage("Registered successful");
        globalJsonResponseBody.setData("Account created successful, please check email inbox to verify your account");
        globalJsonResponseBody.setSuccess(true);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(HttpStatus.CREATED);

        return globalJsonResponseBody;
    }

    @Override
    public GlobalJsonResponseBody loginUser(@Valid UserLoginDTO userLoginDTO) throws UserExistException, VerificationException {

        try {
            String input = userLoginDTO.getPhoneEmailOrUserName();
            String password = userLoginDTO.getPassword();

            // Determine the type of input (phone number, email, or username)
            GlobeUserEntity user = null;
            if (isEmail(input)) {
                user = globeUserRepository.findByEmail(input).orElseThrow(
                        () -> new UserExistException("User with provided email does not exist")
                );
            } else if (isPhoneNumber(input)) {
                user = globeUserRepository.findUserMangerByPhoneNumber(input).orElseThrow(() -> new UserExistException("phone number do not exist"));
            } else {
                user = globeUserRepository.findByUserName(input).orElseThrow(
                        () -> new UserExistException("User with provided username does not exist")
                );
            }
            if (user != null) {

                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                user.getUserName(),
                                password));

                if (!user.getIsVerified()) {
                    throw new VerificationException("Account not verified, please verify");
                }

                SecurityContextHolder.getContext().setAuthentication(authentication);
                String accessToken = tokenProvider.generateAccessToken(authentication);
                String refreshToken = tokenProvider.generateRefreshToken(authentication);

                LoginResponse loginResponse = new LoginResponse();
                loginResponse.setAccessToken(accessToken);
                loginResponse.setRefreshToken(refreshToken);
                loginResponse.setUserData(user);

                GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
                globalJsonResponseBody.setMessage("Login successful");
                globalJsonResponseBody.setData(loginResponse);
                globalJsonResponseBody.setSuccess(true);
                globalJsonResponseBody.setAction_time(new Date());
                globalJsonResponseBody.setHttpStatus(HttpStatus.CREATED);

                return globalJsonResponseBody;

            } else {
                throw new UserExistException("User with provided details does not exist, register");
            }
        } catch (AuthenticationException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    @Override
    public GlobalJsonResponseBody refreshToken(String refreshToken) throws TokenInvalidException {
        try {
            // First validate that this is specifically a refresh token
            if (!tokenProvider.validToken(refreshToken, "REFRESH")) {
                throw new TokenInvalidException("Invalid token");
            }

            // Get username from token
            String userName = tokenProvider.getUserName(refreshToken);

            // Retrieve user from database
            GlobeUserEntity user = globeUserRepository.findByUserName(userName)
                    .orElseThrow(() -> new UserExistException("User not found"));

            // Create authentication with user authorities
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user.getUserName(),
                    null,
                    mapRolesToAuthorities(user.getRoles())
            );

            // Generate only a new access token, not a new refresh token
            String newAccessToken = tokenProvider.generateAccessToken(authentication);

            // Build response
            RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse();
            refreshTokenResponse.setNewToken(newAccessToken);

            GlobalJsonResponseBody response = new GlobalJsonResponseBody();
            response.setMessage("Access token renewed successfully");
            response.setData(refreshTokenResponse);
            response.setSuccess(true);
            response.setAction_time(new Date());
            response.setHttpStatus(HttpStatus.OK);  // Using 200 OK instead of 201 Created

            return response;

        } catch (TokenExpiredException e) {
            throw new TokenInvalidException("Refresh token has expired. Please login again");
        } catch (Exception e) {
            throw new TokenInvalidException("Failed to refresh token: " + e.getMessage());
        } finally {
            // Clear security context after token refresh
            SecurityContextHolder.clearContext();
        }
    }
    @Override
    public List<GlobalJsonResponseBody> getAllUser() {

        List<GlobeUserEntity> userMangerList = globeUserRepository.findAll();
        List<UserRegisterResponseDTO> userRegisterResponseDTOsList = userMangerList.stream()
                .map(this::convertEntityToResponseDTO)
                .toList();
        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage("All users");
        globalJsonResponseBody.setData(userRegisterResponseDTOsList);
        globalJsonResponseBody.setSuccess(true);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(HttpStatus.CREATED);

        return List.of(globalJsonResponseBody);

    }

    @Override
    public GlobalJsonResponseBody getSingleUser(UUID userId) {

        GlobeUserEntity userManger = globeUserRepository.findById(userId).orElseThrow(
                () -> new UserExistException("No such user")
        );

        UserRegisterResponseDTO userDetails = convertEntityToResponseDTO(userManger);

        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage("Single user data retrieved successful");
        globalJsonResponseBody.setData(userDetails);
        globalJsonResponseBody.setSuccess(true);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(HttpStatus.CREATED);

        return globalJsonResponseBody;

    }

    @Override
    public GlobalJsonResponseBody resetPassword(String phoneNumber, String newPassword) {
        return null;
    }


    private String generateUserName(String email) {

        StringBuilder username = new StringBuilder();
        for (int i = 0; i < email.length(); i++) {
            char c = email.charAt(i);
            if (c != '@') {
                username.append(c);
            } else {
                break;
            }
        }
        return username.toString();
    }

    //Todo: convert Entity to DTO
    public UserRegisterDTO convertEntityToDTO(GlobeUserEntity globeUserEntity) {
        return modelMapper.map(globeUserEntity, UserRegisterDTO.class);
    }

    //Todo: convert DTO to Entity
    public GlobeUserEntity convertDTOToEntity(UserRegisterDTO userManagementDTO) {
        return modelMapper.map(userManagementDTO, GlobeUserEntity.class);
    }

    private UserRegisterResponseDTO convertEntityToResponseDTO(GlobeUserEntity globeUserEntity) {
        return modelMapper.map(globeUserEntity, UserRegisterResponseDTO.class);
    }


    private boolean isPhoneNumber(String input) {
        // Regular expression pattern for validating phone numbers
        String phoneRegex = "^\\+(?:[0-9] ?){6,14}[0-9]$";
        // Compile the pattern into a regex pattern object
        Pattern pattern = Pattern.compile(phoneRegex);
        // Use the pattern matcher to test if the input matches the pattern
        return input != null && pattern.matcher(input).matches();
    }

    private boolean isEmail(String input) {
        // Regular expression pattern for validating email addresses
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        // Compile the pattern into a regex pattern object
        Pattern pattern = Pattern.compile(emailRegex);
        // Use the pattern matcher to test if the input matches the pattern
        return input != null && pattern.matcher(input).matches();
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<Roles> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                .collect(Collectors.toList());
    }


}
