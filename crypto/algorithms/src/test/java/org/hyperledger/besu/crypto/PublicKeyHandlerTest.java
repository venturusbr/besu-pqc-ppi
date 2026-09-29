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
package org.hyperledger.besu.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/**
 * The RLPx and DiscV5 handshakes are classical whatever the node's DSA, so they need the secp256k1
 * half of a possibly hybrid key.
 */
class PublicKeyHandlerTest {

  @Test
  void takesTheClassicalHalfOfAHybridKey() {
    final CompositePublicKey hybridKey =
        (CompositePublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();

    final SECPPublicKey classicalKey = PublicKeyHandler.secp256k1(hybridKey);

    assertThat(classicalKey.getEncoded()).isEqualTo(hybridKey.getFirstKey().getEncoded());
  }

  @Test
  void returnsAClassicalKeyUnchanged() {
    final SECPPublicKey publicKey =
        (SECPPublicKey) SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey();

    assertThat(PublicKeyHandler.secp256k1(publicKey)).isSameAs(publicKey);
  }

  @Test
  void rejectsAKeyWithNoClassicalHalf() {
    final MLDSAPublicKey mldsaKey =
        (MLDSAPublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();

    assertThatThrownBy(() -> PublicKeyHandler.secp256k1(mldsaKey))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("secp256k1");
  }

  @Test
  void rejectsAHybridKeyWhoseFirstHalfIsNotClassical() {
    final var mldsa =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.MLDSA44.getName()).get();
    final CompositePublicKey reversed =
        CompositePublicKey.create(
            mldsa.generateNodeKeyPair().getPublicKey(),
            SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey());

    assertThatThrownBy(() -> PublicKeyHandler.secp256k1(reversed))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theClassicalHalfIsTheLeadingBytesOfTheEncoding() {
    final CompositePublicKey hybridKey =
        (CompositePublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();

    // the node id layout the vnt scheme and the enode both rely on
    assertThat(Bytes.wrap(PublicKeyHandler.secp256k1(hybridKey).getEncoded()))
        .isEqualTo(
            Bytes.wrap(hybridKey.getEncoded())
                .slice(0, DSAParametersSet.SECP256K1.getPublicKeyLength()));
  }
}
