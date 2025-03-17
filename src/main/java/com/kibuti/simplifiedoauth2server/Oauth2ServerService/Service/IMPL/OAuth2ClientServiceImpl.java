package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Service.IMPL;

import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.ItemReadyExistException;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Entity.ClientEntity;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Payload.OAuth2ClientRegistrationDTO;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Repo.ClientRepository;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Service.OAuth2ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OAuth2ClientServiceImpl implements OAuth2ClientService {

    //This is internal to the class
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public GlobalJsonResponseBody registerClient(OAuth2ClientRegistrationDTO registrationDTO) throws ItemReadyExistException {
        String clientId = generateClientId();
        // Check if the client ID already exists
        if (clientRepository.existsByClientId(clientId)) {
            throw new ItemReadyExistException("Failed to generate client ID, please try again");
        }

        // Generate client secret
        String rawSecret = generateClientSecret();
        String encodedSecret = passwordEncoder.encode(rawSecret);

        // Create new registered client
        ClientEntity client = new ClientEntity();
        client.setClientId(clientId);
        client.setClientName(registrationDTO.getClientName());
        client.setClientSecret(encodedSecret);

        // Set authentication methods
        Set<String> authMethods = new HashSet<>();
        authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
        authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
        client.setClientAuthenticationMethods(authMethods);

        // Set grant types
        Set<String> grantTypes = new HashSet<>();
        grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN.getValue());

        if (registrationDTO.getAllowClientCredentials()) {
            grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
        }

        client.setAuthorizationGrantTypes(grantTypes);

        // Parse and set redirect URIs
        Set<String> redirectUris = Arrays.stream(registrationDTO.getRedirectUris().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        client.setRedirectUris(redirectUris);

        // Parse and set scopes
        Set<String> scopes = Arrays.stream(registrationDTO.getScopes().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        client.setScopes(scopes);

        // Set additional properties
        client.setClientIdIssuedAt(Instant.now());
        client.setClientSecretExpiresAt(null); // Never expires
        client.setRequireAuthorizationConsent(registrationDTO.getRequireAuthConsent());
        client.setRequireProofKey(registrationDTO.getRequirePkce());

        ClientEntity savedClient = clientRepository.save(client);


        return getGlobalJsonResponseBody("Client registered successfully", savedClient, HttpStatus.CREATED);

    }


    @Override
    public GlobalJsonResponseBody getClientById(String clientId) {

       ClientEntity client = clientRepository.findByClientId(clientId).orElseThrow(() -> new NoSuchElementException("Client not found"));

        return getGlobalJsonResponseBody("Client found", client, HttpStatus.OK);
    }

    private String generateClientId() {
        // Create a byte array of 16 random bytes
        byte[] randomBytes = new byte[16];
        new java.security.SecureRandom().nextBytes(randomBytes);

        // Convert the byte array to a hexadecimal string
        StringBuilder sb = new StringBuilder();
        for (byte b : randomBytes) {
            sb.append(String.format("%02x", b)); // Format each byte as a 2-digit hex value
        }
        // Add the "client_" prefix and return the result
        return "client_" + sb.toString();
    }


    public String generateClientSecret() {
        // Use SecureRandom to generate a 256-character secret
        byte[] randomBytes = new byte[128]; // 128 bytes = 256 hex characters
        new java.security.SecureRandom().nextBytes(randomBytes);

        // Convert the byte array to a hexadecimal string
        StringBuilder sb = new StringBuilder();
        for (byte b : randomBytes) {
            sb.append(String.format("%02x", b)); // Convert each byte to a 2-digit hex value
        }

        return sb.toString(); // Returns a 256-character hex string
    }


    private static GlobalJsonResponseBody getGlobalJsonResponseBody(String message, Object data, HttpStatus httpStatus) {

        GlobalJsonResponseBody globalJsonResponseBody = new GlobalJsonResponseBody();
        globalJsonResponseBody.setMessage(message);
        globalJsonResponseBody.setData(data);
        globalJsonResponseBody.setSuccess(true);
        globalJsonResponseBody.setAction_time(new Date());
        globalJsonResponseBody.setHttpStatus(httpStatus);
        return globalJsonResponseBody;

    }

}
