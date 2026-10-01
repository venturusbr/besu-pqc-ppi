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

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.NodeKeyProvider;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.HandshakeException;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.Handshaker;

import java.security.InvalidAlgorithmParameterException;
import java.util.Optional;
import java.security.PublicKey;

import io.netty.buffer.ByteBuf;
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

  /**
   * The whole exchange, with real ECDH on both sides rather than a stubbed key agreement.
   *
   * <p>ECIES is elliptic-curve only, so a hybrid node key takes part through its classical half
   * and the ML-DSA-44 half plays no role here. That is what this pins down: if the RLPx handshake
   * ever needs to be post-quantum, ECIES itself has to be replaced, not patched.
   */
  @Test
  void twoHybridNodeKeysCompleteTheHandshakeAndAgreeOnSecrets()
      throws InvalidAlgorithmParameterException, HandshakeException {
    final KeyPair initiatorKeys = hybridKeyPair();
    final KeyPair responderKeys = hybridKeyPair();
    final NodeKey initiatorNodeKey = hybridNodeKey(initiatorKeys);
    final NodeKey responderNodeKey = hybridNodeKey(responderKeys);

    final ECIESHandshaker initiator = new ECIESHandshaker();
    final ECIESHandshaker responder = new ECIESHandshaker();

    initiator.prepareInitiator(
        initiatorNodeKey, PublicKeyHandler.secp256k1(responderKeys.getPublicKey()));
    responder.prepareResponder(responderNodeKey);

    final Optional<ByteBuf> responderReply = responder.handleMessage(initiator.firstMessage());
    assertThat(responderReply).isPresent();
    assertThat(initiator.handleMessage(responderReply.get())).isEmpty();

    assertThat(initiator.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(responder.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);

    // the point of a handshake: both ends derived the same material
    assertThat(initiator.secrets().getAesSecret()).isEqualTo(responder.secrets().getAesSecret());
    assertThat(initiator.secrets().getMacSecret()).isEqualTo(responder.secrets().getMacSecret());
    assertThat(initiator.secrets().getToken()).isEqualTo(responder.secrets().getToken());
  }

  @Test
  void theResponderLearnsTheInitiatorsClassicalHalfOnly()
      throws InvalidAlgorithmParameterException, HandshakeException {
    final KeyPair initiatorKeys = hybridKeyPair();
    final KeyPair responderKeys = hybridKeyPair();

    final ECIESHandshaker initiator = new ECIESHandshaker();
    final ECIESHandshaker responder = new ECIESHandshaker();
    initiator.prepareInitiator(
        hybridNodeKey(initiatorKeys), PublicKeyHandler.secp256k1(responderKeys.getPublicKey()));
    responder.prepareResponder(hybridNodeKey(responderKeys));

    responder.handleMessage(initiator.firstMessage());

    // RLPx identifies the peer by its secp256k1 key, so the id it ends up with is 64 bytes and
    // not the 1376-byte hybrid node id that discovery advertises
    assertThat(responder.partyPubKey())
        .isEqualTo(PublicKeyHandler.secp256k1(initiatorKeys.getPublicKey()));
  }

  /** A node key over a hybrid pair that signs hybrid and does ECDH with its classical half. */
  private static NodeKey hybridNodeKey(final KeyPair keyPair) {
    final DigitalSignatureAlgorithm algorithm =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName()).get();
    final SECPPrivateKey classicalPrivateKey =
        (SECPPrivateKey) ((CompositePrivateKey) keyPair.getPrivateKey()).getFirstKey();

    return new NodeKey(
        new NodeKeyProvider() {
          @Override
          public Signature sign(final Bytes32 data) {
            return algorithm.sign(data, keyPair.getPrivateKey());
          }

          @Override
          public PublicKey getPublicKey() {
            return keyPair.getPublicKey();
          }

          @Override
          public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
            return SignatureAlgorithmFactory.getInstance()
                .calculateECDHKeyAgreement(
                    classicalPrivateKey, PublicKeyHandler.secp256k1(partyKey));
          }
        });
  }

  private static KeyPair hybridKeyPair() throws InvalidAlgorithmParameterException {
    return new SupportedAlgorithms()
        .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
        .get()
        .generateNodeKeyPair();
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
