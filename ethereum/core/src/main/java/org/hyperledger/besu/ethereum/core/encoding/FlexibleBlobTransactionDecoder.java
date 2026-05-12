package org.hyperledger.besu.ethereum.core.encoding;

import java.math.BigInteger;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.AccessListEntry;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.VersionedHash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

public class FlexibleBlobTransactionDecoder {
    private FlexibleBlobTransactionDecoder(){}

    public static Transaction decode(final Bytes input){
        return readTransactionPayload(input);
    }

    private static Transaction readTransactionPayload(final Bytes input) {
        final Transaction.Builder builder = Transaction.builder();
        final RLPInput txRlp = RLP.input(input.slice(1));

        builder.sizeForBlockInclusion(input.size())
                .hash(Hash.hash(input));
        readTransactionPayloadInner(builder, txRlp);

        return builder.build();
    }

    public static void readTransactionPayloadInner(final Transaction.Builder builder, final RLPInput txRlp){
        txRlp.enterList();
        final Short dsaType = txRlp.readShort();
        final DSAParametersSet dsaParams = DSAParametersSet.fromId(dsaType);
        final BigInteger chainId = txRlp.readBigIntegerScalar();
        builder
            .type(TransactionType.FLEXIBLE_BLOB)
            .dsaType(dsaType)
            .chainId(chainId)
            .nonce(txRlp.readLongScalar())
            .maxPriorityFeePerGas(Wei.of(txRlp.readUInt256Scalar()))
            .maxFeePerGas(Wei.of(txRlp.readUInt256Scalar()))
            .gasLimit(txRlp.readLongScalar())
            .to(txRlp.readBytes(v -> v.isEmpty() ? null : Address.wrap(v)))
            .value(Wei.of(txRlp.readUInt256Scalar()))
            .payload(txRlp.readBytes())
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
            .maxFeePerBlobGas(Wei.of(txRlp.readUInt256Scalar()))
            .versionedHashes(
                txRlp.readList(versionedHashes -> new VersionedHash(versionedHashes.readBytes32())))
            .providedPublicKey(PublicKeyDecoder.decodeByDsaId(dsaType, txRlp));
            
            builder
                .signature(
                    txRlp.readBytes(signatureBytes -> SignatureFactory.createSignatureFromBytes(signatureBytes, dsaParams))
                );
        txRlp.leaveList();
    }
}
