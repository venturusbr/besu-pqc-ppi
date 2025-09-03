package org.hyperledger.besu.crypto.signature;

import static com.google.common.base.Preconditions.checkArgument;
import org.apache.tuweni.bytes.Bytes;

public class SignatureFactory {
    public static Signature createStrongNestedConcSignature(Signature first, Signature second){
        Bytes firstSignatureBytes = first.encodedBytes();
        Bytes secondSignatureBytes = second.encodedBytes();

        Bytes hybridSignatureBytes = Bytes.concatenate(firstSignatureBytes, secondSignatureBytes);

        SingleSignature hybridSignature = new SingleSignature(hybridSignatureBytes, true);

        checkArgument(firstSignatureBytes.size() + secondSignatureBytes.size() == hybridSignature.encodedBytes().size(), "encoded HybridSignature must be the same size as the sum of the first and second signatures");

        return hybridSignature;
    }
}
