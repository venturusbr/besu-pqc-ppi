package org.hyperledger.besu.ethereum.core.encoding;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.AccessListEntry;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleAccessListTransactionEncoder {
    public static void encode(final Transaction transaction, final RLPOutput out){
        out.startList();
        encodeAccessListInner(
            transaction.getDsaType(),
            transaction.getChainId(),
            transaction.getNonce(),
            transaction.getGasPrice().orElseThrow(),
            transaction.getGasLimit(),
            transaction.getTo(),
            transaction.getValue(),
            transaction.getMaybePublicKey(),
            transaction.getPayload(),
            transaction
                .getAccessList()
                .orElseThrow(
                    () ->
                        new IllegalStateException(
                            "Developer error: access list should be guaranteed to be present")), out);
        TransactionSignatureEncoder.writeSignatureBytes(transaction.getSignature(), out);
        out.endList();
    }

    public static void encodeAccessListInner(
        final Optional<Short> dsaType,
        final Optional<BigInteger> chainId,
        final long nonce,
        final Wei gasPrice,
        final long gasLimit,
        final Optional<Address> to,
        final Wei value,
        final Optional<PublicKey> pk,
        final Bytes payload,
        final List<AccessListEntry> accessList,
        final RLPOutput out){
        out.writeShort(dsaType.get());
        AccessListTransactionEncoder.encodeAccessListInner(
            chainId,
            nonce,
            gasPrice,
            gasLimit,
            to,
            value,
            payload,
            accessList,
            out
        );
        out.writeBytes(Bytes.wrap(pk.get().getEncoded()));
    }
}
