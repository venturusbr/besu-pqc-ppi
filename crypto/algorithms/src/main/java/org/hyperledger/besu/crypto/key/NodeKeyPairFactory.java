package org.hyperledger.besu.crypto.key;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.key.types.CompositeDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositeDSAPublicKey;
import org.hyperledger.besu.crypto.key.types.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.DSAPublicKey;

public class NodeKeyPairFactory {
    private NodeKeyPairFactory(){}

    public static NodeKeyPair createFromKeyPair(final KeyPair kp, final String algorithmName){
        return create(Bytes.wrap(kp.getPrivate().getEncoded()),Bytes.wrap(kp.getPublic().getEncoded()), algorithmName);
    }

    public static NodeKeyPair create(final Bytes privateKeyBytes, final Bytes publicKeyBytes, final String algorithmName){
        //todo: we need to create key based on algorithm 
       PrivateKey sk = new DSAPrivateKey(algorithmName, "RAW", privateKeyBytes);

       PublicKey pk = new DSAPublicKey(algorithmName, "RAW", publicKeyBytes);

       return new NodeKeyPair(sk, pk);
    }

    public static NodeKeyPair createHybrid(
        final PrivateKey firstSk,
        final PrivateKey secondSk,
        final PublicKey firstPk,
        final PublicKey secondPk) {
        PrivateKey sk = new CompositeDSAPrivateKey(firstSk, secondSk);
        PublicKey pk = new CompositeDSAPublicKey(firstPk, secondPk);

        return new NodeKeyPair(sk, pk);
    }
}
