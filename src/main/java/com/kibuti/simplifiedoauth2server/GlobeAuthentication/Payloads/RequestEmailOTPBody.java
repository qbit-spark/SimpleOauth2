package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RequestEmailOTPBody {
    @NotBlank(message = "Email is mandatory")
    @Email(message = "Email should be valid")
    private String email;
}
