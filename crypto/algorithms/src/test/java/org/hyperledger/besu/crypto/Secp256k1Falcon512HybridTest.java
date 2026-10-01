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
package org.hyperledger.besu.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.algorithms.Falcon512;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.key.types.Falcon512PrivateKey;
import org.hyperledger.besu.crypto.key.types.Falcon512PublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;
import org.hyperledger.besu.crypto.signature.types.Falcon512Signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/**
 * SECP256K1-FALCON512: SECP256K1 signs the data, Falcon-512 signs the data followed by the SECP256K1
 * signature, and the two are concatenated. SECP256K1's signature is fixed-length and comes first,
 * so Falcon's variable-length signature is recovered as the remainder.
 */
class Secp256k1Falcon512HybridTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1FALCON512;
  private static final int SECP_SIG = DSAParametersSet.SECP256K1.getSignatureLength();
  private static final Bytes DATA = Hash.keccak256(Bytes.fromHexString("0xc0ffee"));

  private final DigitalSignatureAlgorithm hybrid =
      new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();

  @Test
  void isRegisteredUnderItsIdAndCannotRecoverItsKey() {
    assertThat(DSAParametersSet.fromId((short) 0x0061)).isEqualTo(HYBRID);
    assertThat(hybrid).isInstanceOf(HybridDigitalSignatureAlgorithm.class);
    assertThat(hybrid).isNotInstanceOf(PublicKeyRecoverable.class);
    assertThat(hybrid.getDsaParametersSet()).isEqualTo(HYBRID);
  }

  @Test
  void generatedKeysHaveTheDeclaredSizes() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();

    assertThat(keyPair.getPrivateKey().getEncoded()).hasSize(HYBRID.getPrivateKeyLength());
    assertThat(keyPair.getPublicKey().getEncoded()).hasSize(HYBRID.getPublicKeyLength());
  }

  @Test
  void signatureVerifies() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();

    assertThat(hybrid.verify(DATA, hybrid.sign(DATA, keyPair.getPrivateKey()), keyPair.getPublicKey()))
        .isTrue();
  }

  @Test
  void signaturesOfDifferentLengthsAllSplitAtTheSecpBoundaryAndVerify() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Set<Integer> totalLengths = new HashSet<>();

    for (int i = 0; i < 30; i++) {
      final Bytes data = Hash.keccak256(Bytes.ofUnsignedInt(i));
      final CompositeSignature signed = (CompositeSignature) hybrid.sign(data, keyPair.getPrivateKey());
      final Bytes wire = signed.encodedBytes();
      totalLengths.add(wire.size());

      final CompositeSignature decoded =
          (CompositeSignature) SignatureFactory.createSignatureFromBytes(wire, HYBRID);

      assertThat(decoded.getFirstSignature().encodedBytes())
          .isEqualTo(signed.getFirstSignature().encodedBytes());
      assertThat(decoded.getSecondSignature()).isEqualTo(signed.getSecondSignature());
      assertThat(hybrid.verify(data, decoded, keyPair.getPublicKey())).isTrue();
    }
    // Only meaningful if the Falcon tail actually varied.
    assertThat(totalLengths).hasSizeGreaterThan(1);
  }

  @Test
  void signatureLengthIsBoundedOnBothSides() {
    assertThatThrownBy(
            () -> SignatureFactory.createSignatureFromBytes(Bytes.wrap(new byte[SECP_SIG]), HYBRID))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                SignatureFactory.createSignatureFromBytes(
                    Bytes.wrap(new byte[SECP_SIG + Falcon512Signature.MAX_LENGTH + 1]), HYBRID))
        .isInstanceOf(IllegalArgumentException.class);

    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Bytes secpHalf =
        ((CompositeSignature) hybrid.sign(DATA, keyPair.getPrivateKey()))
            .getFirstSignature()
            .encodedBytes();
    final Signature longest =
        SignatureFactory.createSignatureFromBytes(
            Bytes.concatenate(secpHalf, Bytes.wrap(new byte[Falcon512Signature.MAX_LENGTH])),
            HYBRID);
    assertThat(((CompositeSignature) longest).getSecondSignature().encodedBytes().size())
        .isEqualTo(Falcon512Signature.MAX_LENGTH);
  }

  @Test
  void tamperingWithEitherHalfFailsVerification() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Bytes wire = hybrid.sign(DATA, keyPair.getPrivateKey()).encodedBytes();

    // Inside the SECP256K1 half (r), and inside the Falcon half.
    final Signature secpTampered =
        SignatureFactory.createSignatureFromBytes(flipByte(wire, 10), HYBRID);
    final Signature falconTampered =
        SignatureFactory.createSignatureFromBytes(flipByte(wire, SECP_SIG + 100), HYBRID);

    assertThat(hybrid.verify(DATA, secpTampered, keyPair.getPublicKey())).isFalse();
    assertThat(hybrid.verify(DATA, falconTampered, keyPair.getPublicKey())).isFalse();
  }

  @Test
  void falconHalfIsBoundToTheSecpSignature() {
    // Strong nesting: Falcon signs the data followed by the SECP256K1 signature, so the Falcon
    // half cannot be detached and reused against the bare data.
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final CompositeSignature signed = (CompositeSignature) hybrid.sign(DATA, keyPair.getPrivateKey());
    final PublicKey falconPk = ((CompositePublicKey) keyPair.getPublicKey()).getSecondKey();
    final Falcon512 falcon = new Falcon512();

    assertThat(falcon.verify(DATA, signed.getSecondSignature(), falconPk)).isFalse();
    assertThat(
            falcon.verify(
                Bytes.concatenate(DATA, signed.getFirstSignature().encodedBytes()),
                signed.getSecondSignature(),
                falconPk))
        .isTrue();
  }

  @Test
  void privateKeySurvivesAByteRoundTripAndStillSigns() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();

    final PrivateKey reloaded =
        KeyFactory.createPrivateKey(
            Bytes.wrap(keyPair.getPrivateKey().getEncoded()),
            HYBRID,
            PrivateKeyRepresentation.EXPANDED,
            PrivateKeyRepresentation.EXPANDED);

    final CompositePrivateKey original = (CompositePrivateKey) keyPair.getPrivateKey();
    final CompositePrivateKey decoded = (CompositePrivateKey) reloaded;
    assertThat(decoded.getFirstKey().getEncoded()).isEqualTo(original.getFirstKey().getEncoded());
    assertThat(decoded.getSecondKey()).isEqualTo(original.getSecondKey());
    assertThat(hybrid.verify(DATA, hybrid.sign(DATA, reloaded), keyPair.getPublicKey())).isTrue();
  }

  @Test
  void publicKeyIsDerivableFromThePrivateKey() {
    // KeyManager rebuilds a node public key from its private key file alone.
    final KeyPair keyPair = hybrid.generateNodeKeyPair();

    final PublicKey derived = KeyFactory.createPublicKey(keyPair.getPrivateKey(), HYBRID);

    assertThat(derived.getEncoded()).isEqualTo(keyPair.getPublicKey().getEncoded());
  }

  @Test
  void fullAndFalconOnlyPublicKeysDecode() {
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final CompositePublicKey original = (CompositePublicKey) keyPair.getPublicKey();

    final CompositePublicKey full =
        (CompositePublicKey)
            KeyFactory.createPublicKey(Bytes.wrap(original.getEncoded()), HYBRID).orElseThrow();
    // Compared by bytes: SECPPublicKey.equals also compares an algorithm label, which differs
    // between generated keys and keys decoded through KeyFactory.
    assertThat(full.getFirstKey().getEncoded()).isEqualTo(original.getFirstKey().getEncoded());
    assertThat(full.getSecondKey()).isEqualTo(original.getSecondKey());

    // What a transaction carries: the SECP256K1 half is recovered from its signature.
    final PublicKey falconOnly =
        KeyFactory.createPublicKey(Bytes.wrap(original.getSecondKey().getEncoded()), HYBRID)
            .orElseThrow();
    assertThat(falconOnly).isEqualTo(original.getSecondKey());
  }

  @Test
  void keysOfTheWrongSizeAreRefused() {
    assertThatThrownBy(
            () ->
                KeyFactory.createPublicKey(
                    Bytes.wrap(new byte[HYBRID.getPublicKeyLength() - 1]), HYBRID))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                KeyFactory.createPrivateKey(
                    Bytes.wrap(new byte[HYBRID.getPrivateKeyLength() - 1]),
                    HYBRID,
                    PrivateKeyRepresentation.EXPANDED,
                    PrivateKeyRepresentation.EXPANDED))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(HYBRID.getPrivateKeyLength())
        .isEqualTo(DSAParametersSet.SECP256K1.getPrivateKeyLength() + Falcon512PrivateKey.LENGTH);
    assertThat(HYBRID.getPublicKeyLength())
        .isEqualTo(DSAParametersSet.SECP256K1.getPublicKeyLength() + Falcon512PublicKey.LENGTH);
  }

  private static Bytes flipByte(final Bytes bytes, final int index) {
    final byte[] copy = bytes.toArray();
    copy[index] ^= 0x01;
    return Bytes.wrap(copy);
  }
}
