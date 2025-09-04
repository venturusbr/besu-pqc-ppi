package org.hyperledger.besu.crypto.providers;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.signature.Signature;

public interface DSAProvider {
    Signature signMessage(final Bytes data);
    Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk);
    void loadNodeKeyPair();
}
