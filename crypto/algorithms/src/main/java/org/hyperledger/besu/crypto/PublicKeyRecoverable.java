package org.hyperledger.besu.crypto;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.signature.Signature;

public interface PublicKeyRecoverable {
    Optional<PublicKey> recoverPublicKeyFromSignature(final Bytes32 data, final Signature signature);
}
