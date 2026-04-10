package org.hyperledger.besu.ethereum.core.encoding;

import java.math.BigInteger;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.AccessListEntry;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

public class FlexibleEIP1559TransactionDecoder {
    private FlexibleEIP1559TransactionDecoder() {}

    public static Transaction decode(final Bytes input){
        final RLPInput txRlp = RLP.input(input.slice(1));
        txRlp.enterList();
        final Short dsaType = txRlp.readShort();
        final DSAParametersSet dsaParams = DSAParametersSet.fromId(dsaType);
        final BigInteger chainId = txRlp.readBigIntegerScalar();
        final Transaction.Builder builder = 
            Transaction.builder()
                .type(TransactionType.FLEXIBLE_EIP1559)
                .dsaType(dsaType)
                .chainId(chainId)
                .nonce(txRlp.readLongScalar())
                .maxPriorityFeePerGas(Wei.of(txRlp.readUInt256Scalar()))
                .maxFeePerGas(Wei.of(txRlp.readUInt256Scalar()))
                .gasLimit(txRlp.readLongScalar())
                .to(txRlp.readBytes(v -> v.isEmpty() ? null : Address.wrap(v)))
                .value(Wei.of(txRlp.readUInt256Scalar()))
                .payload(txRlp.readBytes())
                .rawRlp(txRlp.raw())
                .accessList(
                    txRlp.readList(
                        accessListEntryRLPInput -> {
                            accessListEntryRLPInput.enterList();
                            final AccessListEntry accessListEntry =
                                new AccessListEntry(
                                    Address.wrap(accessListEntryRLPInput.readBytes()),
                                    accessListEntryRLPInput.readList(RLPInput::readBytes32));
                            accessListEntryRLPInput.leaveList();
                            return accessListEntry;
                        }))
                .publicKey(txRlp.readBytes(pkBytes -> pkBytes.isEmpty() ? null : KeyFactory.createPublicKey(pkBytes, dsaParams)))
                .sizeForAnnouncement(input.size())
                .sizeForBlockInclusion(input.size())
                .hash(Hash.hash(input));
        final Transaction transaction = 
            builder
                .signature(
                    txRlp.readBytes(signatureBytes -> SignatureFactory.createSignatureFromBytes(signatureBytes, dsaParams))
                )
                .build();
        txRlp.leaveList();
        return transaction;
    }
}
