package org.hyperledger.besu.crypto.key;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class KeyExtractor {
    public Bytes extractPrivateKeyBytesAtOffset(
            final Bytes keyBytes,
            final Integer fromIndex,
            final DSAParametersSet params,
            final PrivateKeyRepresentation representation) {

        final Integer length;
        switch (representation) {
            case EXPANDED:
                length = params.getPrivateKeyLength();
                break;
            case SEED:
                length = params.getSeedLength();
                break;
            default:
                throw new IllegalArgumentException("Unsupported private key representation: " + representation);
        }

        return keyBytes.slice(fromIndex, length);
    }

    public Bytes extractPublicKeyBytesAtOffset(
            final Bytes keyBytes,
            final Integer fromIndex,
            final DSAParametersSet params) {

        final Integer length = params.getPublicKeyLength();
        if (length == null || length <= 0) {
            throw new IllegalArgumentException("Public key length is invalid for " + params.getName());
        }

        return keyBytes.slice(fromIndex, length);
    }
}
