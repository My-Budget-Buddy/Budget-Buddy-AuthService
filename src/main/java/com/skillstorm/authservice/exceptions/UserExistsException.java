package com.skillstorm.authservice.exceptions;

public class UserExistsException extends Exception {

    public UserExistsException(String message) {
        super(message);
    }

}
