package org.hyperledger.besu.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

public interface DigitalSignatureAlgorithm {
    Signature sign(final Bytes data, final PrivateKey sk);

    Boolean verify(final Bytes data, final Signature signature, final PublicKey pk);

    KeyPair generateNodeKeyPair();

    DSAParametersSet getDsaParametersSet();
}
