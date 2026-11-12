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
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.ethereum.core.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

public class FlexibleCodeDelegationDecoder {
  public static CodeDelegation decode(final Bytes input) {
    final RLPInput cdRlp = RLP.input(input.slice(1)); // Skip the code delegation type byte
    cdRlp.enterList();
    final CodeDelegationType type = CodeDelegationType.FLEXIBLE;
    final Optional<Short> dsaType = Optional.ofNullable(cdRlp.readShort());
    final DSAParametersSet dsaParams = DSAParametersSet.fromId(dsaType.get());
    final BigInteger chainId = cdRlp.readBigIntegerScalar();
    final Address address = Address.wrap(cdRlp.readBytes());
    final long nonce = cdRlp.readLongScalar();
    final Optional<PublicKey> maybePk = PublicKeyDecoder.decodeByDsaId(dsaParams.getId(), cdRlp);

    final Signature signature =
        cdRlp.readBytes(
            signatureBytes -> SignatureFactory.createSignatureFromBytes(signatureBytes, dsaParams));

    cdRlp.leaveList();

    return new CodeDelegation(type, dsaType, chainId, address, nonce, maybePk, signature);
  }
}
