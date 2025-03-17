package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class EmailOTPRequestBody {

    @NotBlank(message = "Email is mandatory")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "OTP code is mandatory")
    @Pattern(regexp = "\\d{6}", message = "OTP code must be a 6-digit number")
    private String code;
}
