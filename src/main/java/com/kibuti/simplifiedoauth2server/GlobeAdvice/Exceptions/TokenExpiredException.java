package com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions;

public class TokenExpiredException extends Exception{
    public TokenExpiredException(String message){
        super(message);
    }
}
