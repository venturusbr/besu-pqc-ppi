package org.hyperledger.besu.crypto;

public class SignatureValidationContext {
    private final Boolean disallowMalleability;

    public SignatureValidationContext(final Boolean disallowMalleability) {
        this.disallowMalleability = disallowMalleability;
    }

    public Boolean isDisallowMalleability() {
        return disallowMalleability;
    }
}
