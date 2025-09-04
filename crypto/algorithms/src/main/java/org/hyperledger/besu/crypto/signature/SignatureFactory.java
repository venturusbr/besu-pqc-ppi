package org.hyperledger.besu.crypto.signature;

import static com.google.common.base.Preconditions.*;

public class SignatureFactory {
    public static CompositeSignature createCompositeStrongNestedConcSignature(SingleSignature first, SingleSignature second){
        CompositeSignature hybridSignature = new CompositeSignature(first, second);

        checkArgument(first.getEncodedBytes().size() + second.getEncodedBytes().size() == hybridSignature.getEncodedBytes().size(), "encoded HybridSignature must be the same size as the sum of the first and second signatures");

        return hybridSignature;
    }
}
