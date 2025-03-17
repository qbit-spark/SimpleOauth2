package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Payloads;

import lombok.Data;

@Data
public class RefreshTokenResponse {
    String newToken;
}
