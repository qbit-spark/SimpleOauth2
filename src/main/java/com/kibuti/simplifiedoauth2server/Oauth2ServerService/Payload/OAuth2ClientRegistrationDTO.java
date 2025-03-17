package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Payload;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OAuth2ClientRegistrationDTO {
    private String clientId; // If null, a UUID will be generated

    @NotBlank(message = "Client name is required")
    private String clientName;

    @NotBlank(message = "Redirect URIs are required")
    private String redirectUris; // Comma-separated list

    @NotBlank(message = "Scopes are required")
    private String scopes; // Comma-separated list

    private Boolean requireAuthConsent = true;
    private Boolean requirePkce = false;
    private Boolean allowClientCredentials = false;

}
