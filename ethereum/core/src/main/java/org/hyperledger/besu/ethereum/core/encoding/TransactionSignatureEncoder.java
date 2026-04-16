package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import org.apache.tuweni.bytes.Bytes;

public class TransactionSignatureEncoder {

    public static void writeSignatureBytes(final Signature signature, final RLPOutput out){
        Bytes signatureBytes = signature.encodedBytes();
        out.writeBytes(signatureBytes);
    }
    public static void writeSignatureAndV(final Transaction transaction, final RLPOutput out) {
        SECPSignature secpSignature = (SECPSignature) transaction.getSignature();
        out.writeBigIntegerScalar(transaction.getV());
        writeStandardSignature(secpSignature, out);
    }

    public static void writeStandardSignatureAndRecoveryId(final Signature signature, final RLPOutput out) {
        SECPSignature secpSignature = (SECPSignature) signature;
        out.writeIntScalar(secpSignature.getRecId());
        writeStandardSignature(secpSignature, out);
    }

    private static void writeStandardSignature(final SECPSignature secpSignature, final RLPOutput out) {
        out.writeBigIntegerScalar(secpSignature.getR());
        out.writeBigIntegerScalar(secpSignature.getS());
    }
}
