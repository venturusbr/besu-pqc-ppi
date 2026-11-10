/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.kzg.Blob;
import org.hyperledger.besu.ethereum.core.kzg.KZGCommitment;
import org.hyperledger.besu.ethereum.core.kzg.KZGProof;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.util.List;

import org.apache.tuweni.bytes.Bytes;

public class FlexibleBlobPooledTransactionDecoder {
  private FlexibleBlobPooledTransactionDecoder() {}

  public static Transaction decode(final Bytes input) {
    final RLPInput txRlp = RLP.input(input.slice(1));
    txRlp.enterList();
    Integer versionId = 0;
    final Transaction.Builder builder = Transaction.builder();
    FlexibleBlobTransactionDecoder.readTransactionPayloadInner(builder, txRlp);

    Boolean hasVersionId = !txRlp.nextIsList();
    if (hasVersionId) {
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
