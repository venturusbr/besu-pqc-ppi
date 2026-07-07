package org.hyperledger.besu.crypto.providers;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.Signature;

public interface DSAProvider {
    DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId);
    DSAParametersSet getActiveDsaParametersSet();
    Signature signMessage(final Bytes data);
    Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk);
    void loadNodeKeyPair();
}
