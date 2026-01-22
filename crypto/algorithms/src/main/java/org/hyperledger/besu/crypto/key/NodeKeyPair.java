package org.hyperledger.besu.crypto.key;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.PrivateKey;
import java.security.PublicKey;


public class NodeKeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public NodeKeyPair(final PrivateKey sk, final PublicKey pk){
        checkNotNull(sk);
        checkNotNull(pk);
        this.privateKey = sk;
        this.publicKey = pk;
    }

    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    public PublicKey getPublicKey(){
        return publicKey;
    }
}
