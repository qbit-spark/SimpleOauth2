package com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserExistException extends UsernameNotFoundException {
    public UserExistException(String message){
        super(message);
    }
}
