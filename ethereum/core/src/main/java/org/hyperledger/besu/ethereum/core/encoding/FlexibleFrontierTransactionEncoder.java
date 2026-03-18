package org.hyperledger.besu.ethereum.core.encoding;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.BytesHolder;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleFrontierTransactionEncoder {
    public static void encode(final Transaction transaction, final RLPOutput out){
        out.startList();
        out.writeShort(transaction.getDsaType().orElseThrow());
        out.writeLongScalar(transaction.getNonce());
        out.writeUInt256Scalar(transaction.getGasPrice().orElseThrow());
        out.writeLongScalar(transaction.getGasLimit());
        out.writeBytes(
            transaction.getTo().map(BytesHolder::getBytes).map(Bytes::copy).orElse(Bytes.EMPTY));
        out.writeUInt256Scalar(transaction.getValue());
        out.writeBytes(transaction.getPayload());
        out.writeBytes(Bytes.wrap(transaction.getMaybePublicKey().get().getEncoded()));
        TransactionSignatureEncoder.writeSignatureBytes(transaction.getSignature(), out);
        out.endList();;
    }
}
