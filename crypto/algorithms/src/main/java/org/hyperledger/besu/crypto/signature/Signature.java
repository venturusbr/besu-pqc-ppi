package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;

public interface Signature {
    String getAlgorithm();
    Bytes encodedBytes();
}
