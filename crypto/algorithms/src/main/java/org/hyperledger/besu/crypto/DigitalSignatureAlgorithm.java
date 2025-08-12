package org.hyperledger.besu.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.key.NodeKeyPair;
import org.hyperledger.besu.crypto.signature.Signature;

public interface DigitalSignatureAlgorithm {

    String getAlgorithmName();

    String getParameterSet();

    Signature sign(final Bytes data, final PrivateKey sk);

    Boolean verify(final Bytes data, final Signature signature, final PublicKey pk);

    NodeKeyPair generateKeyPair();

    Integer signatureLength();

    Integer privateKeyLength();

    Integer publicKeyLength();

    Boolean supportsPKR();

    Boolean isHybrid();
}
