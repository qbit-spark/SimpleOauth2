package com.kibuti.simplifiedoauth2server.GlobeAuthentication.DTOs;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokenDTO {
    @NotBlank(message = "Refresh token should not be empty")
    String refreshToken;
}
