package org.hyperledger.besu.crypto.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.key.format.DSAPrivateKey;
import org.hyperledger.besu.crypto.key.format.DSAPublicKey;

public class KeyExtractor {
    public PrivateKey extractPrivateKeyAtOffset(Bytes skBytes, int fromIndex, int toIndex, String algorithmName, String format) {
        Bytes slicedSk = skBytes.slice(fromIndex, toIndex);
        return new DSAPrivateKey(algorithmName, format, slicedSk);
    }

    public PublicKey extractPublicKeyAtOffset(Bytes pkBytes, int fromIndex, int toIndex, String algorithmName, String format) {
        Bytes slicedPk = pkBytes.slice(fromIndex, toIndex);
        return new DSAPublicKey(algorithmName, format, slicedPk);
    }
}
