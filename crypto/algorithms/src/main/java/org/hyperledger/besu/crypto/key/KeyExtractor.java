package org.hyperledger.besu.crypto.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.key.types.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.DSAPublicKey;

public class KeyExtractor {
    public PrivateKey extractPrivateKeyAtOffset(final Bytes skBytes, final int fromIndex, final int toIndex, final String algorithmName, final String format) {
        Bytes slicedSk = skBytes.slice(fromIndex, toIndex);
        return new DSAPrivateKey(algorithmName, format, slicedSk);
    }

    public PublicKey extractPublicKeyAtOffset(final Bytes pkBytes, final int fromIndex, final int toIndex, final String algorithmName, final String format) {
        Bytes slicedPk = pkBytes.slice(fromIndex, toIndex);
        return new DSAPublicKey(algorithmName, format, slicedPk);
    }
}
