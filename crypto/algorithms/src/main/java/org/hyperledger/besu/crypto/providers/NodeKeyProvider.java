package org.hyperledger.besu.crypto.providers;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.signature.Signature;

public interface NodeKeyProvider {
    Signature sign(final Bytes32 data);
    PublicKey getPublicKey();
    Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey);
}
