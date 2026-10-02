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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/**
 * For a hybrid whose classical half is recoverable, only the other half travels with the payload.
 * The classical half has to be recovered from the signature, so a payload that states it, by
 * carrying the whole composite key, is rejected.
 */
class PublicKeyDecoderTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  private final DigitalSignatureAlgorithm hybrid =
      new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();

  @Test
  void decodesTheHalfThatCannotBeRecovered() {
    final CompositePublicKey key = (CompositePublicKey) hybridKeyPair().getPublicKey();

    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    PublicKeyEncoder.encodeByDsa(key, hybrid, out);

    final Optional<PublicKey> decoded =
        PublicKeyDecoder.decodeByDsa(hybrid, new BytesValueRLPInput(out.encoded(), false));

    assertThat(decoded).isPresent();
    assertThat(decoded.get().getEncoded()).isEqualTo(key.getSecondKey().getEncoded());
  }

  @Test
  void rejectsTheWholeCompositeKey() {
    final PublicKey key = hybridKeyPair().getPublicKey();

    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    out.writeBytes(Bytes.wrap(key.getEncoded()));

    assertThatThrownBy(
            () ->
                PublicKeyDecoder.decodeByDsa(hybrid, new BytesValueRLPInput(out.encoded(), false)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private KeyPair hybridKeyPair() {
    return hybrid.generateNodeKeyPair();
  }
}
