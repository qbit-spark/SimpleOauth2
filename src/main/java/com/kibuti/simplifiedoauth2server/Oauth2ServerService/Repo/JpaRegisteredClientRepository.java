package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Repo;

import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Entity.ClientEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

/***
 *  Bro, this is very important, this class is responsible for the conversion of the entity to the registered client ready for OAUTH2
 */
@Component
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final TokenSettings tokenSettings;
    private final ClientSettings clientSettings;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(java.util.UUID.fromString(id))
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(ClientEntity entity) {
        Set<ClientAuthenticationMethod> authMethods = entity.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::new)
                .collect(Collectors.toSet());

        Set<AuthorizationGrantType> grantTypes = entity.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::new)
                .collect(Collectors.toSet());

        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId().toString())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientName(entity.getClientName())
                .clientIdIssuedAt(entity.getClientIdIssuedAt())
                .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
                .clientAuthenticationMethods(methods -> methods.addAll(authMethods))
                .authorizationGrantTypes(types -> types.addAll(grantTypes))
                .redirectUris(uris -> uris.addAll(entity.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(entity.getScopes()))
                .tokenSettings(tokenSettings)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(entity.isRequireAuthorizationConsent())
                        .requireProofKey(entity.isRequireProofKey())
                        .build());

        return builder.build();
    }
}
