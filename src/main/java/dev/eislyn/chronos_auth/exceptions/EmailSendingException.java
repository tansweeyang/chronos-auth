package dev.eislyn.chronos_auth.exceptions;

public class EmailSendingException extends RuntimeException{
    public EmailSendingException(String message) {
        super(message);
    }
}
