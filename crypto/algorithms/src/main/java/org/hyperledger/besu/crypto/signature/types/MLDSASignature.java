package org.hyperledger.besu.crypto.signature.types;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.SignatureValidationContext;
import org.hyperledger.besu.crypto.signature.Signature;

public class MLDSASignature implements Signature{
    private final Bytes encodedBytes;
    private final String algorithmName;

    private MLDSASignature(final String algorithmName, final Bytes encodedBytes){
        this.algorithmName = algorithmName;
        this.encodedBytes = encodedBytes;
    }

    @Override
    public String getAlgorithm() {
        return algorithmName;
    }

    @Override
    public Bytes encodedBytes() {
        return encodedBytes;
    }

    @Override
    public Boolean isValid(final SignatureValidationContext context){
        return encodedBytes != null && !encodedBytes.isEmpty();
    }
    

    public static MLDSASignature create(final String algorithmName, final Bytes encodedBytes){
        return new MLDSASignature(algorithmName, encodedBytes);
    }
}
