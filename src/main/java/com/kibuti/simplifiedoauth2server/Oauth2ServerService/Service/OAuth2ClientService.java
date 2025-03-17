package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Service;

import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.ItemReadyExistException;
import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Payload.OAuth2ClientRegistrationDTO;

public interface OAuth2ClientService {
    GlobalJsonResponseBody registerClient(OAuth2ClientRegistrationDTO registrationDTO) throws ItemReadyExistException;
    GlobalJsonResponseBody getClientById(String clientId);
}
