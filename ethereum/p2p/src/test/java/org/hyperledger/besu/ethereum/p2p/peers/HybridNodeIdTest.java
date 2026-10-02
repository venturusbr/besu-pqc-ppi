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
package org.hyperledger.besu.ethereum.p2p.peers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A node id carries the whole node key, so its size follows the node's active DSA rather than being
 * fixed at the 64 bytes of a secp256k1 key.
 */
class HybridNodeIdTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  @AfterEach
  void tearDown() {
    // the provider is process wide state, so it must not leak into the next test
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void nodeIdSizeIsTheSecpKeyLengthWithoutAProvider() {
    assertThat(EnodeURLImpl.nodeIdSize())
        .isEqualTo(DSAParametersSet.SECP256K1.getPublicKeyLength());
  }

  @Test
  void nodeIdSizeFollowsTheActiveDsa() throws InvalidAlgorithmParameterException {
    useHybridDsa();

    assertThat(EnodeURLImpl.nodeIdSize()).isEqualTo(HYBRID.getPublicKeyLength());
  }

  @Test
  void anEnodeAcceptsAHybridNodeIdAndRoundTrips() throws InvalidAlgorithmParameterException {
    useHybridDsa();
    final Bytes nodeId = hybridNodeId();

    final EnodeURLImpl enode =
        (EnodeURLImpl)
            EnodeURLImpl.builder()
                .nodeId(nodeId)
                .ipAddress("127.0.0.1")
                .listeningPort(30303)
                .discoveryPort(30303)
                .build();

    assertThat(enode.getNodeId()).isEqualTo(nodeId);
    assertThat(EnodeURLImpl.fromString(enode.toString()).getNodeId()).isEqualTo(nodeId);
  }

  @Test
  void anEnodeRejectsAClassicalNodeIdWhileTheDsaIsHybrid()
      throws InvalidAlgorithmParameterException {
    useHybridDsa();
    final Bytes classicalNodeId = Bytes.random(DSAParametersSet.SECP256K1.getPublicKeyLength());

    assertThatThrownBy(
            () ->
                EnodeURLImpl.builder()
                    .nodeId(classicalNodeId)
                    .ipAddress("127.0.0.1")
                    .listeningPort(30303)
                    .discoveryPort(30303)
                    .build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid node id of length");
  }

  @Test
  void theClassicalKeyIsTheLeadingPartOfAHybridNodeId() throws InvalidAlgorithmParameterException {
    useHybridDsa();
    final CompositePublicKey publicKey = hybridPublicKey();
    final Bytes nodeId = Bytes.wrap(publicKey.getEncoded());

    final Bytes classicalKey = EnodeURLImpl.secp256k1PublicKey(nodeId);

    // this is the key the RLPx handshake encrypts to
    assertThat(classicalKey).isEqualTo(Bytes.wrap(publicKey.getFirstKey().getEncoded()));
    assertThat(classicalKey.size()).isEqualTo(DSAParametersSet.SECP256K1.getPublicKeyLength());
  }

  @Test
  void aClassicalNodeIdIsAlreadyTheClassicalKey() {
    final Bytes nodeId = Bytes.random(DSAParametersSet.SECP256K1.getPublicKeyLength());

    assertThat(EnodeURLImpl.secp256k1PublicKey(nodeId)).isEqualTo(nodeId);
  }

  private static void useHybridDsa() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1, HYBRID));
    config.setNodeActiveDSA(HYBRID.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  private static CompositePublicKey hybridPublicKey() {
    final DigitalSignatureAlgorithm algorithm =
        new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();
    final KeyPair keyPair = algorithm.generateNodeKeyPair();
    return (CompositePublicKey) keyPair.getPublicKey();
  }

  private static Bytes hybridNodeId() {
    return Bytes.wrap(hybridPublicKey().getEncoded());
  }
}
