package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;


public class SingleSignature implements Signature{
    private final String algorithmName;
    private final Bytes encoded;

    public SingleSignature(Bytes signatureBytes, String algorithmName){
        this.encoded = signatureBytes;
        this.algorithmName = algorithmName;
    }

    @Override
    public String getAlgorithm(){
        return algorithmName;
    }

    @Override
    public Bytes getEncodedBytes(){
        return encoded;
    }
}
