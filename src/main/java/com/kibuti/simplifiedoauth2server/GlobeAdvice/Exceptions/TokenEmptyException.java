package com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions;

public class TokenEmptyException extends Exception{
    public TokenEmptyException(String message){
        super(message);
    }
}
