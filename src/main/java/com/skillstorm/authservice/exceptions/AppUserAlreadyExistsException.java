package com.skillstorm.authservice.exceptions;

public class AppUserAlreadyExistsException extends Exception {

    public AppUserAlreadyExistsException(String message) {
        super(message);
    }

}
