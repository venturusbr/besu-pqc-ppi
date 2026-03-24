package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.apache.tuweni.bytes.Bytes;

public class FlexibleFrontierTransactionDecoder {
    public static Transaction decode(final Bytes input){
        return decode(RLP.input(input));
    }

    public static Transaction decode(final RLPInput transactionRlp){
        int size = transactionRlp.currentSize();
        Short dsaType = transactionRlp.readShort();
        final Transaction.Builder builder = 
            Transaction.builder()
                .type(TransactionType.FRONTIER)
                .nonce(transactionRlp.readLongScalar())
                .gasPrice(Wei.of(transactionRlp.readUInt256Scalar()))
                .gasLimit(transactionRlp.readLongScalar())
                .to(transactionRlp.readBytes(v -> v.isEmpty() ? null : Address.wrap(v)))
                .value(Wei.of(transactionRlp.readUInt256Scalar()))
                .payload(transactionRlp.readBytes())
                .publicKey(transactionRlp.readBytes())
                .rawRlp(transactionRlp.raw())
                .sizeForBlockInclusion(size)
                .sizeForAnnouncement(size)
                .hash(Hash.hash(transactionRlp.raw()));
        final Bytes signatureBytes = transactionRlp.readBytes();
        final Signature signature = SignatureFactory.createSignatureFromBytes(signatureBytes, dsaType);
    }
}
