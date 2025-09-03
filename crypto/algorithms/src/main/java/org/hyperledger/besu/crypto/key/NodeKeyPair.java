package org.hyperledger.besu.crypto.key;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.format.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.DSAPublicKey;
import org.hyperledger.besu.crypto.key.format.CompositeDSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.CompositeDSAPublicKey;

public class NodeKeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private NodeKeyPair(final PrivateKey sk, final PublicKey pk){
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

    public static NodeKeyPair create(Bytes privateKeyBytes, Bytes publicKeyBytes, String algorithmName){
       PrivateKey sk = new DSAPrivateKey(algorithmName, "RAW", privateKeyBytes);

       PublicKey pk = new DSAPublicKey(algorithmName, "RAW", publicKeyBytes);

       return new NodeKeyPair(sk, pk);
    }

    public static NodeKeyPair createHybrid(
        PrivateKey firstSk,
        PrivateKey secondSk,
        PublicKey firstPk,
        PublicKey secondPk) {
        PrivateKey sk = new CompositeDSAPrivateKey(firstSk, secondSk);
        PublicKey pk = new CompositeDSAPublicKey(firstPk, secondPk);

        return new NodeKeyPair(sk, pk);
    }
}
