package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;


public class DSASignature implements Signature{
    private final Bytes encoded;
    private final Boolean isHybrid;

    public DSASignature(Bytes signatureBytes, Boolean isHybrid){
        this.encoded = signatureBytes;
        this.isHybrid = isHybrid;
    }

    public Bytes encodedBytes(){
        return encoded;
    }

    public Boolean isHybrid(){
        return isHybrid;
    }
}
