package org.hyperledger.besu.ethereum.core.encoding;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleCodeDelegationTransactionEncoder {
    public static void encode(final Transaction transaction, final RLPOutput out){
        out.startList();
        out.writeShort(transaction.getDsaType().orElseThrow());
        out.writeBytes(Bytes.wrap(transaction.getMaybePublicKey().get().getEncoded()));
        TransactionSignatureEncoder.writeSignatureBytes(transaction.getSignature(), out);
        out.endList();
    }
}
