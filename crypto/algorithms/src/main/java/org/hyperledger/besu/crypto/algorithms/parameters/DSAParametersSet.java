package org.hyperledger.besu.crypto.algorithms.parameters;

public enum DSAParametersSet {
    SECP256K1("SECP256K1", 32, 64, 65, null),
    SECP256R1("SECP256R1", 32, 64, 65, null),
    MLDSA44("MLDSA44", 2560, 1312, 2420, 32),
    MLDSA65("MLDSA65", 4032, 1952, 3309, 32),
    MLDSA87("MLDSA87", 4896, 2592, 4627, 32),
    SECP256K1MLDSA44("SECP256K1-MLDSA44", 2592, 1376, 2485, null)
    ;

    private final String name;
    private final Integer publicKeyLength;
    private final Integer privateKeyLength;
    private final Integer signatureLength;
    private final Integer seedLength;

    DSAParametersSet(String name, Integer privateKeyLength,  Integer publicKeyLength, Integer signatureLength, Integer seedLength){
        this.name = name;
        this.publicKeyLength = publicKeyLength;
        this.privateKeyLength = privateKeyLength;
        this.signatureLength = signatureLength;
        this.seedLength = seedLength;
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

    public Integer getSeedLength(){
        return seedLength;
    }
}
