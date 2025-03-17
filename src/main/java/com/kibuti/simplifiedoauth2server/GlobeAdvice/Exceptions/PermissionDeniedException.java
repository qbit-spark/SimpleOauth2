package com.kibuti.simplifiedoauth2server.GlobeAdvice.Exceptions;

public class PermissionDeniedException extends Exception{
    public PermissionDeniedException(String message){
        super(message);
    }
}
