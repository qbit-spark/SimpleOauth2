package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "oauth_registered_clients")
public class ClientEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(unique = true)
    private String clientId;

    private String clientName;
    private String clientSecret;

    @ElementCollection
    @CollectionTable(name = "oauth_client_auth_methods",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "auth_method")
    private Set<String> clientAuthenticationMethods;

    @ElementCollection
    @CollectionTable(name = "oauth_client_grant_types",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type")
    private Set<String> authorizationGrantTypes;

    @ElementCollection
    @CollectionTable(name = "oauth_client_redirect_uris",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri")
    private Set<String> redirectUris;

    @ElementCollection
    @CollectionTable(name = "oauth_client_scopes",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope")
    private Set<String> scopes;

    private Instant clientIdIssuedAt;
    private Instant clientSecretExpiresAt;
    private boolean requireProofKey;
    private boolean requireAuthorizationConsent;
}