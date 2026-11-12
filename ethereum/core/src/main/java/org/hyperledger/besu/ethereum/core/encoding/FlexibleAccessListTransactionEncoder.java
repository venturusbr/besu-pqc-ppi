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

import org.hyperledger.besu.datatypes.AccessListEntry;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

public class FlexibleAccessListTransactionEncoder {
  public static void encode(final Transaction transaction, final RLPOutput out) {
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
                        "Developer error: access list should be guaranteed to be present")),
        out);
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
      final RLPOutput out) {
    out.writeShort(dsaType.get());
    AccessListTransactionEncoder.encodeAccessListInner(
        chainId, nonce, gasPrice, gasLimit, to, value, payload, accessList, out);
    // A transaction whose key is recovered whole from its signature carries no key, and the
    // decoder reads none back for it.
    pk.ifPresent(publicKey -> PublicKeyEncoder.encodeByDsaId(publicKey, dsaType.get(), out));
  }
}
