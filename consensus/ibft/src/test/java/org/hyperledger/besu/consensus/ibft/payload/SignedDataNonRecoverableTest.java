/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.consensus.ibft.payload;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.consensus.common.bft.ConsensusRoundIdentifier;
import org.hyperledger.besu.consensus.common.bft.payload.SignedData;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;

import java.security.InvalidAlgorithmParameterException;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Covers the code paths that only execute when the active algorithm cannot recover a public key
 * from a signature. Under SECP256K1 -- which every other consensus test uses -- recovery is itself
 * the proof of authorship, so the public key is never written to the wire and the verification
 * branch in {@link SignedData#create} never runs. These tests install ML-DSA-44 as the active
 * algorithm so those branches are actually exercised.
 */
public class SignedDataNonRecoverableTest {

  private static final ConsensusRoundIdentifier ROUND_IDENTIFIER =
      new ConsensusRoundIdentifier(1, 0);
  private static final Hash DIGEST = Hash.fromHexStringLenient("0x1337");

  private final DigitalSignatureAlgorithm mldsa = new MLDSA(DSAParametersSet.MLDSA44);

  @BeforeEach
  public void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration dsaConfig =
        new DigitalSignatureAlgorithmConfiguration();
    dsaConfig.setNodeActiveDSA(DSAParametersSet.MLDSA44.getName());
    // No KeyConfiguration is required: nothing here loads a node key from disk, it only
    // resolves the active algorithm and its parameters.
    DSAProviderFactory.setDsaProvider(dsaConfig, null);
  }

  @AfterEach
  public void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  public void mldsaIsNotRecoverableOtherwiseTheseTestsProveNothing() {
    assertThat(DSAProviderFactory.getActiveDSA()).isNotInstanceOf(PublicKeyRecoverable.class);
  }

  @Test
  public void publicKeySurvivesAWireRoundTripAndYieldsTheSameAuthor() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final PreparePayload payload = new PreparePayload(ROUND_IDENTIFIER, DIGEST);
    final SignedData<PreparePayload> signed = sign(payload, keyPair);

    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    signed.writeTo(out);
    final SignedData<PreparePayload> decoded =
        PayloadDeserializers.readSignedPreparePayloadFrom(RLP.input(out.encoded()));

    assertThat(decoded.getPublicKey()).isPresent();
    assertThat(decoded.getPublicKey().get().getEncoded())
        .isEqualTo(keyPair.getPublicKey().getEncoded());
    assertThat(decoded.getAuthor()).isEqualTo(signed.getAuthor());
    assertThat(decoded.getAuthor()).isEqualTo(Address.extract(keyPair.getPublicKey()));
    assertThat(decoded.getPayload()).isEqualTo(payload);
  }

  @Test
  public void signatureOverDifferentDataIsRejected() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final PreparePayload payload = new PreparePayload(ROUND_IDENTIFIER, DIGEST);

    // A well-formed signature by the claimed author, but over a different message.
    final Signature wrongSignature =
        mldsa.sign(Bytes.fromHexStringLenient("0xdeadbeef"), keyPair.getPrivateKey());

    assertThatThrownBy(
            () ->
                SignedData.create(
                    payload, wrongSignature, Optional.of(keyPair.getPublicKey())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Signature verification failed");
  }

  @Test
  public void signatureFromADifferentKeyIsRejected() {
    final KeyPair signingKeyPair = mldsa.generateNodeKeyPair();
    final KeyPair impersonatedKeyPair = mldsa.generateNodeKeyPair();
    final PreparePayload payload = new PreparePayload(ROUND_IDENTIFIER, DIGEST);

    final Signature signature =
        mldsa.sign(
            Bytes.wrap(payload.hashForSignature().getBytes()), signingKeyPair.getPrivateKey());

    // Claiming someone else's public key must not yield their address: resolvePublicKey trusts
    // the supplied key blindly, so verification is the only thing standing in the way.
    assertThatThrownBy(
            () ->
                SignedData.create(
                    payload, signature, Optional.of(impersonatedKeyPair.getPublicKey())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Signature verification failed");
  }

  @Test
  public void locallySignedMessagesCarryTheirPublicKeyWithoutVerifying() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final PreparePayload payload = new PreparePayload(ROUND_IDENTIFIER, DIGEST);
    final Signature signature =
        mldsa.sign(Bytes.wrap(payload.hashForSignature().getBytes()), keyPair.getPrivateKey());

    final SignedData<PreparePayload> signed =
        SignedData.createLocallySigned(payload, signature, Optional.of(keyPair.getPublicKey()));

    assertThat(signed.getAuthor()).isEqualTo(Address.extract(keyPair.getPublicKey()));
    assertThat(signed.getPublicKey()).isPresent();
  }

  private SignedData<PreparePayload> sign(final PreparePayload payload, final KeyPair keyPair) {
    final Signature signature =
        mldsa.sign(Bytes.wrap(payload.hashForSignature().getBytes()), keyPair.getPrivateKey());
    return SignedData.create(payload, signature, Optional.of(keyPair.getPublicKey()));
  }
}
