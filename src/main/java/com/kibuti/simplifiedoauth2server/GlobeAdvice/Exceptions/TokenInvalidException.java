package com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions;

public class TokenInvalidException extends Exception{
    public TokenInvalidException(String message){
        super(message);
    }
}
