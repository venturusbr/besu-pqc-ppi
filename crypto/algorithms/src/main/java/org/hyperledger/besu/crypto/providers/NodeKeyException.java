package org.hyperledger.besu.crypto.providers;

public class NodeKeyException extends RuntimeException {
    public NodeKeyException(){}
    
    public NodeKeyException(final String message){
        super(message);
    }

    public NodeKeyException(final String message, final Throwable cause){
        super(message, cause);
    }
    public NodeKeyException(final Throwable cause){
        super(cause);
    }

    public NodeKeyException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace){
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
