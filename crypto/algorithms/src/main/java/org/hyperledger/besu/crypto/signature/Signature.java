package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.SignatureValidationContext;

public interface Signature {
    String getAlgorithm();
    Bytes encodedBytes();
    Boolean isValid(SignatureValidationContext context);
}
