package org.hyperledger.besu.crypto.signature;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import org.apache.tuweni.bytes.Bytes;

public class SignatureFactory {
    private SignatureFactory(){}

    public static CompositeSignature createCompositeStrongNestedConcSignature(SingleSignature first, SingleSignature second){
        CompositeSignature hybridSignature = new CompositeSignature(first, second);

        checkArgument(first.encodedBytes().size() + second.encodedBytes().size() == hybridSignature.encodedBytes().size(), "encoded HybridSignature must be the same size as the sum of the first and second signatures");

        return hybridSignature;
    }

    public static SingleSignature createSingleSignatureFromBytes(byte[] signatureBytes, String algorithmName){
        checkNotNull(signatureBytes);
        checkNotNull(algorithmName);
        return new SingleSignature(Bytes.wrap(signatureBytes), algorithmName);
    }
}
