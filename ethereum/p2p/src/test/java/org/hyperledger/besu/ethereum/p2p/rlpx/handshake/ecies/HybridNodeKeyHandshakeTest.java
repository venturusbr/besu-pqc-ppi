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
package org.hyperledger.besu.ethereum.p2p.rlpx.handshake.ecies;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.cryptoservices.NodeKey;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * The RLPx handshake is classical whatever the node's DSA, so it has to take the secp256k1 half of
 * a hybrid node key instead of casting the key it is handed.
 */
class HybridNodeKeyHandshakeTest {

  @Test
  void anInitiatorWithAHybridNodeKeyProducesItsFirstMessage() {
    final CompositePublicKey hybridKey = hybridPublicKey();
    final NodeKey nodeKey = nodeKeyReturning(hybridKey);
    final SECPPublicKey peerKey =
        (SECPPublicKey) SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey();
    final ECIESHandshaker handshaker = new ECIESHandshaker();

    handshaker.prepareInitiator(nodeKey, peerKey);

    // before the fix this threw ClassCastException and no RLPx connection could be opened
    assertThat(handshaker.firstMessage()).isNotNull();
  }

  @Test
  void theHandshakeUsesTheClassicalHalfOfTheNodeKey() {
    final CompositePublicKey hybridKey = hybridPublicKey();

    final SECPPublicKey classicalKey = PublicKeyHandler.secp256k1(hybridKey);

    assertThat(classicalKey.getEncoded()).isEqualTo(hybridKey.getFirstKey().getEncoded());
    assertThat(classicalKey.getEncoded().length)
        .isEqualTo(DSAParametersSet.SECP256K1.getPublicKeyLength());
  }

  private static NodeKey nodeKeyReturning(final PublicKey publicKey) {
    final NodeKey nodeKey = mock(NodeKey.class);
    when(nodeKey.getPublicKey()).thenReturn(publicKey);
    when(nodeKey.calculateECDHKeyAgreement(any())).thenReturn(Bytes32.ZERO);
    return nodeKey;
  }

  private static CompositePublicKey hybridPublicKey() {
    final KeyPair keyPair =
        new SupportedAlgorithms()
            .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
            .get()
            .generateNodeKeyPair();
    return (CompositePublicKey) keyPair.getPublicKey();
  }
}
