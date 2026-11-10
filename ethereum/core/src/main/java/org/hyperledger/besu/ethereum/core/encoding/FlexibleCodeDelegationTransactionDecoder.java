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

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.AccessListEntry;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.math.BigInteger;

import org.apache.tuweni.bytes.Bytes;

public class FlexibleCodeDelegationTransactionDecoder {
  private FlexibleCodeDelegationTransactionDecoder() {}

  public static Transaction decode(final Bytes input) {
    final RLPInput txRlp = RLP.input(input.slice(1));
    txRlp.enterList();
    final Short dsaType = txRlp.readShort();
    final DSAParametersSet dsaParams = DSAParametersSet.fromId(dsaType);
    final BigInteger chainId = txRlp.readBigIntegerScalar();
    final Transaction.Builder builder =
        Transaction.builder()
            .type(TransactionType.FLEXIBLE_DELEGATE_CODE)
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
            .codeDelegations(
                txRlp.readList(
                    authorizationRLPInput ->
                        CodeDelegationDecoder.decodeRLP(authorizationRLPInput)))
            .providedPublicKey(PublicKeyDecoder.decodeByDsaId(dsaType, txRlp))
            .sizeForAnnouncement(input.size())
            .sizeForBlockInclusion(input.size())
            .hash(Hash.hash(input));
    final Transaction transaction =
        builder
            .signature(
                txRlp.readBytes(
                    signatureBytes ->
                        SignatureFactory.createSignatureFromBytes(signatureBytes, dsaParams)))
            .build();
    txRlp.leaveList();
    return transaction;
  }
}
