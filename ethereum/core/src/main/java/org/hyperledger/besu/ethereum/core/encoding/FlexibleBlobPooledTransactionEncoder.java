package org.hyperledger.besu.ethereum.core.encoding;

import static org.hyperledger.besu.datatypes.BlobType.KZG_CELL_PROOFS;
import static org.slf4j.LoggerFactory.getLogger;

import java.security.InvalidParameterException;

import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.kzg.Blob;
import org.hyperledger.besu.ethereum.core.kzg.KZGCommitment;
import org.hyperledger.besu.ethereum.core.kzg.KZGProof;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;
import org.slf4j.Logger;

public class FlexibleBlobPooledTransactionEncoder {
    private static final Logger LOG = getLogger(BlobPooledTransactionEncoder.class);
    static final String NO_BLOBS_ERROR =
        "Transaction with no blobsWithCommitments cannot be encoded for Pooled Transaction";
    
    public static void encode(final Transaction transaction, final RLPOutput out){
        LOG.trace("Encoding transaction with blobs {}", transaction);
        var blobsWithCommitments = transaction.getBlobsWithCommitments();
        if (blobsWithCommitments.isEmpty() || blobsWithCommitments.get().getBlobs().isEmpty()) {
        throw new InvalidParameterException(NO_BLOBS_ERROR);
        }
        out.startList();
        FlexibleBlobTransactionEncoder.encode(transaction, out);
        if(blobsWithCommitments.get().getBlobType() == KZG_CELL_PROOFS) {
            out.writeIntScalar(blobsWithCommitments.get().getBlobType().getVersionId());
        }
        out.writeList(blobsWithCommitments.get().getBlobs(), Blob::writeTo);
        out.writeList(blobsWithCommitments.get().getKzgCommitments(), KZGCommitment::writeTo);
        out.writeList(blobsWithCommitments.get().getKzgProofs(), KZGProof::writeTo);
        out.endList();
    }
}
