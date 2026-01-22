package org.hyperledger.besu.crypto;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.signature.Signature;

public interface PublicKeyRecoverable {
    PublicKey recoverPublicKeyFromSignature(final Bytes data, final Signature signature);
}
