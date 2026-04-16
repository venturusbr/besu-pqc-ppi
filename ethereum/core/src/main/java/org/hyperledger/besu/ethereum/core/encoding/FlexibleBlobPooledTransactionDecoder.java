package org.hyperledger.besu.ethereum.core.encoding;

import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.kzg.Blob;
import org.hyperledger.besu.ethereum.core.kzg.KZGCommitment;
import org.hyperledger.besu.ethereum.core.kzg.KZGProof;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

public class FlexibleBlobPooledTransactionDecoder {
    private FlexibleBlobPooledTransactionDecoder(){}

    public static Transaction decode(final Bytes input){
        final RLPInput txRlp = RLP.input(input.slice(1));
        txRlp.enterList();
        Integer versionId = 0;
        final Transaction.Builder builder = Transaction.builder();
        FlexibleBlobTransactionDecoder.readTransactionPayloadInner(builder, txRlp);

        Boolean hasVersionId = !txRlp.nextIsList();
        if(hasVersionId){
            versionId = txRlp.readIntScalar();
        }
        List<Blob> blobs = txRlp.readList(Blob::readFrom);
        List<KZGCommitment> commitments = txRlp.readList(KZGCommitment::readFrom);
        List<KZGProof> proofs = txRlp.readList(KZGProof::readFrom);
        txRlp.leaveList();

        return builder
            .kzgBlobs(BlobType.of(versionId), commitments, blobs, proofs)
            .sizeForAnnouncement(input.size())
            .build();
    }
}
