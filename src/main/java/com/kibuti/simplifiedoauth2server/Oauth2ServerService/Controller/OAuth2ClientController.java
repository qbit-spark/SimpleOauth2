package com.kibuti.simplifiedoauth2server.Oauth2ServerService.Controller;


import com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions.ItemReadyExistException;

import com.kibuti.simplifiedoauth2server.GlobeResponseBody.GlobalJsonResponseBody;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Payload.OAuth2ClientRegistrationDTO;
import com.kibuti.simplifiedoauth2server.Oauth2ServerService.Service.OAuth2ClientService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("api/v2/oauth")
public class OAuth2ClientController {

    private final OAuth2ClientService oAuth2ClientService;

    @PostMapping("/clients")
    public ResponseEntity<GlobalJsonResponseBody> registerClient(@Valid @RequestBody OAuth2ClientRegistrationDTO registrationDTO)
            throws ItemReadyExistException {
        GlobalJsonResponseBody response = oAuth2ClientService.registerClient(registrationDTO);
        return new ResponseEntity<>(response, response.getHttpStatus());
    }

    @GetMapping("/clients/{clientId}")
    public ResponseEntity<GlobalJsonResponseBody> getClient(@PathVariable String clientId) {
        GlobalJsonResponseBody response = oAuth2ClientService.getClientById(clientId);
        return new ResponseEntity<>(response, response.getHttpStatus());
    }
}