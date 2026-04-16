package org.hyperledger.besu.crypto.signature;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class SignatureExtractor {
    public Bytes extractSignatureBytesAtOffset(
            final Bytes signatureBytes,
            final Integer fromIndex,
            final DSAParametersSet params) {

        final Integer length = params.getSignatureLength();

        if (length == null || length <= 0) {
            throw new IllegalArgumentException(
                "Signature length is invalid for " + params.getName());
        }

        return signatureBytes.slice(fromIndex, length);
    }
}
