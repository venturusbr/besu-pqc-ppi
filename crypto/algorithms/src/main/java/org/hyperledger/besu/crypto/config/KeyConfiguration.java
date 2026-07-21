package org.hyperledger.besu.crypto.config;

import java.io.File;

import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;

public class KeyConfiguration {
    private final File nodePrivateKeyFile;
    private final PrivateKeyRepresentation firstDSASkRepresentation;
    private final PrivateKeyRepresentation secondDSASkRepresentation;

    private KeyConfiguration(final PrivateKeyRepresentation firstDSASkRepresentation, final PrivateKeyRepresentation secondDSASKeyRepresentation, final File nodePrivateKeyFile){
        this.firstDSASkRepresentation = firstDSASkRepresentation;
        this.secondDSASkRepresentation = secondDSASKeyRepresentation;
        this.nodePrivateKeyFile = nodePrivateKeyFile;
    }

    public static KeyConfiguration createSingleKeyConfig(
            final File nodePrivateKeyFile,
            final PrivateKeyRepresentation representation) {
        return new KeyConfiguration(representation, null, nodePrivateKeyFile);
    }

    // algoritmo híbrido — duas representações
    public static KeyConfiguration createHybridKeyConfig(
            final File nodePrivateKeyFile,
            final PrivateKeyRepresentation first,
            final PrivateKeyRepresentation second) {
        return new KeyConfiguration(first, second, nodePrivateKeyFile);
    }

    public boolean isHybrid() {
        return secondDSASkRepresentation != null;
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
