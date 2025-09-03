package org.hyperledger.besu.crypto.algorithms.parameters;

public enum DSAParametersSet {
    SECP256K1("secp256k1", 32, 64, 65),
    MLDSA44("MLDSA44", 2626, 1334, 2420),
    MLDSA65("MLDSA65", 4098, 1974, 3309),
    MLDSA87("MLDSA87", 4962, 2614, 4627),
    SECP256K1MLDSA65("SECP256k1-MLDSA65", 4130, 2038, 3374)
    ;

    private final String name;
    private final Integer publicKeyLength;
    private final Integer privateKeyLength;
    private final Integer signatureLength;

    DSAParametersSet(String name, Integer privateKeyLength,  Integer publicKeyLength, Integer signatureLength){
        this.name = name;
        this.publicKeyLength = publicKeyLength;
        this.privateKeyLength = privateKeyLength;
        this.signatureLength = signatureLength;
    }

    public String getName(){
        return name;
    }

    public Integer getPublicKeyLength(){
        return publicKeyLength;
    }
    
    public Integer getPrivateKeyLength(){
        return privateKeyLength;
    }

    public Integer getSignatureLength(){
        return signatureLength;
    }
}
