package org.hyperledger.besu.crypto.config;

import java.io.File;

import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;

public class KeyConfiguration {
    private final File nodePrivateKeyFile;
    private final PrivateKeyRepresentation firstDSASkRepresentation;
    private final PrivateKeyRepresentation secondDSASkRepresentation;

    public KeyConfiguration(final PrivateKeyRepresentation firstDSASkRepresentation, final PrivateKeyRepresentation secondDSASKeyRepresentation, final File nodePrivateKeyFile){
        this.firstDSASkRepresentation = firstDSASkRepresentation;
        this.secondDSASkRepresentation = secondDSASKeyRepresentation;
        this.nodePrivateKeyFile = nodePrivateKeyFile;
    }

    public File getNodePrivateKeyFile(){
        return nodePrivateKeyFile;
    }

    public PrivateKeyRepresentation getFirstKeyRepresentation(){
        return firstDSASkRepresentation;
    }
    public PrivateKeyRepresentation getSecondKeyRepresentation(){
        return secondDSASkRepresentation;
    }
}
