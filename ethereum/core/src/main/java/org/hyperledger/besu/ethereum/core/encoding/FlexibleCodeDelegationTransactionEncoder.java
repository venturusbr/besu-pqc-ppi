package org.hyperledger.besu.ethereum.core.encoding;

import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.BytesHolder;
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleCodeDelegationTransactionEncoder {
    public static void encodeCodeDelegationInner(final List<CodeDelegation> payloads, final RLPOutput rlpOutput){
        rlpOutput.startList();
        payloads.forEach( payload -> encodeSingleFlexibleCodeDelegation(payload, rlpOutput));
        rlpOutput.endList();
    }

    public static void encodeSingleFlexibleCodeDelegation(final CodeDelegation payload, final RLPOutput rlpOutput){
        rlpOutput.startList();
        CodeDelegationTransactionEncoder.encodeAuthorizationDetails(payload, rlpOutput);
        rlpOutput.writeBytes(payload.signature().encodedBytes());
        rlpOutput.endList();
        
    }
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
        encodeCodeDelegationInner(
            transaction
                .getCodeDelegationList()
                .orElseThrow(
                    () ->
                        new IllegalStateException(
                            "Developer error: the transaction should be guaranteed to have a code delegation authorizations here")),
            out);
        out.writeBytes(Bytes.wrap(transaction.getMaybePublicKey().get().getEncoded()));
        TransactionSignatureEncoder.writeSignatureBytes(transaction.getSignature(), out);
        out.endList();
    }
}
