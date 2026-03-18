package org.hyperledger.besu.ethereum.core.encoding;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.BytesHolder;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleBlobTransactionEncoder {
    public static void encode(final Transaction transaction, final RLPOutput out){
        out.startList();
        out.writeShort(transaction.getDsaType().orElseThrow());
        out.writeBigIntegerScalar(transaction.getChainId().orElseThrow());
        out.writeLongScalar(transaction.getNonce());
        out.writeUInt256Scalar(transaction.getMaxPriorityFeePerGas().orElseThrow());
        out.writeUInt256Scalar(transaction.getMaxFeePerGas().orElseThrow());
        out.writeLongScalar(transaction.getGasLimit());
        out.writeBytes(
            transaction.getTo().map(BytesHolder::getBytes).map(Bytes::copy).orElse(Bytes.EMPTY));
        out.writeUInt256Scalar(transaction.getValue());
        out.writeBytes(transaction.getPayload());
        AccessListTransactionEncoder.writeAccessList(out, transaction.getAccessList());
        out.writeUInt256Scalar(transaction.getMaxFeePerBlobGas().orElseThrow());
        out.startList();
        transaction
            .getVersionedHashes()
            .get()
            .forEach(
                vh -> {
                out.writeBytes(vh.getBytes());
                });
        out.endList();
        out.writeBytes(Bytes.wrap(transaction.getMaybePublicKey().get().getEncoded()));
        TransactionSignatureEncoder.writeSignatureBytes(transaction.getSignature(), out);
        out.endList();
    }
}
