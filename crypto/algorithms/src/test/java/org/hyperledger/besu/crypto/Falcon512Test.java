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
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;
import org.hyperledger.besu.crypto.key.types.Falcon512PrivateKey;
import org.hyperledger.besu.crypto.key.types.Falcon512PublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureExtractor;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.crypto.signature.types.Falcon512Signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class Falcon512Test {

  private static final Bytes MESSAGE = Bytes.fromHexString("0xdeadbeefcafebabe");

  private final Falcon512 falcon = new Falcon512();

  @Test
  void isNotRecoverableSoTransactionsMustCarryTheKey() {
    assertThat(falcon).isNotInstanceOf(PublicKeyRecoverable.class);
    assertThat(falcon.getDsaParametersSet()).isEqualTo(DSAParametersSet.FALCON512);
    assertThat(DSAParametersSet.fromId((short) 0x0040)).isEqualTo(DSAParametersSet.FALCON512);
  }

  @Test
  void generatedKeysHaveTheDeclaredSizesAndThePublicKeyIsDerivableFromThePrivateKey() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();

    assertThat(keyPair.getPrivateKey().getEncoded())
        .hasSize(DSAParametersSet.FALCON512.getPrivateKeyLength());
    assertThat(keyPair.getPublicKey().getEncoded())
        .hasSize(DSAParametersSet.FALCON512.getPublicKeyLength());
    // KeyManager rebuilds a node public key from its private key file alone.
    assertThat(KeyFactory.createPublicKey(keyPair.getPrivateKey(), DSAParametersSet.FALCON512))
        .isEqualTo(keyPair.getPublicKey());
  }

  @Test
  void signatureVerifies() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Signature signature = falcon.sign(MESSAGE, keyPair.getPrivateKey());

    assertThat(falcon.verify(MESSAGE, signature, keyPair.getPublicKey())).isTrue();
  }

  @Test
  void signatureOverDifferentDataIsRejected() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Signature signature = falcon.sign(MESSAGE, keyPair.getPrivateKey());

    assertThat(falcon.verify(Bytes.fromHexString("0x01"), signature, keyPair.getPublicKey()))
        .isFalse();
  }

  @Test
  void signatureFromADifferentKeyIsRejected() {
    final KeyPair signer = falcon.generateNodeKeyPair();
    final KeyPair other = falcon.generateNodeKeyPair();
    final Signature signature = falcon.sign(MESSAGE, signer.getPrivateKey());

    assertThat(falcon.verify(MESSAGE, signature, other.getPublicKey())).isFalse();
  }

  @Test
  void signaturesAreVariableLengthAndAllVerify() {
    // The property that rules out any fixed-length assumption, such as hybrid concatenation.
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Set<Integer> lengths = new HashSet<>();
    for (int i = 0; i < 40; i++) {
      final Bytes message = Bytes.ofUnsignedInt(i);
      final Signature signature = falcon.sign(message, keyPair.getPrivateKey());
      lengths.add(signature.encodedBytes().size());
      assertThat(falcon.verify(message, signature, keyPair.getPublicKey())).isTrue();
    }
    assertThat(lengths).hasSizeGreaterThan(1);
  }

  @Test
  void malformedInputFailsVerificationInsteadOfThrowing() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Signature genuine = falcon.sign(MESSAGE, keyPair.getPrivateKey());

    final Signature garbage =
        Falcon512Signature.create(Bytes.wrap(new byte[genuine.encodedBytes().size()]));
    final Signature truncated = Falcon512Signature.create(genuine.encodedBytes().slice(0, 10));
    final PublicKey shortKey = wrongLengthKey(Falcon512PublicKey.LENGTH - 1);

    assertThat(falcon.verify(MESSAGE, garbage, keyPair.getPublicKey())).isFalse();
    assertThat(falcon.verify(MESSAGE, truncated, keyPair.getPublicKey())).isFalse();
    assertThat(falcon.verify(MESSAGE, genuine, shortKey)).isFalse();
  }

  @Test
  void keysSurviveAByteRoundTripThroughKeyFactory() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();

    final PrivateKey reloadedSk =
        KeyFactory.createPrivateKey(
            Bytes.wrap(keyPair.getPrivateKey().getEncoded()),
            DSAParametersSet.FALCON512,
            PrivateKeyRepresentation.EXPANDED,
            null);
    final PublicKey reloadedPk =
        KeyFactory.createPublicKey(
                Bytes.wrap(keyPair.getPublicKey().getEncoded()), DSAParametersSet.FALCON512)
            .orElseThrow();

    assertThat(reloadedSk).isEqualTo(keyPair.getPrivateKey());
    assertThat(reloadedPk).isEqualTo(keyPair.getPublicKey());
    // A reloaded private key must still sign for the original public key.
    assertThat(falcon.verify(MESSAGE, falcon.sign(MESSAGE, reloadedSk), keyPair.getPublicKey()))
        .isTrue();
  }

  @Test
  void signatureSurvivesAByteRoundTripThroughSignatureFactory() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Signature signature = falcon.sign(MESSAGE, keyPair.getPrivateKey());

    final Signature decoded =
        SignatureFactory.createSignatureFromBytes(
            signature.encodedBytes(), DSAParametersSet.FALCON512);

    assertThat(decoded).isInstanceOf(Falcon512Signature.class).isEqualTo(signature);
  }

  @Test
  void equalityIsByValueNotIdentity() {
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Bytes pkBytes = Bytes.wrap(keyPair.getPublicKey().getEncoded());
    final Bytes skBytes = Bytes.wrap(keyPair.getPrivateKey().getEncoded());
    final Bytes sigBytes = falcon.sign(MESSAGE, keyPair.getPrivateKey()).encodedBytes();

    assertEqualByValue(Falcon512PublicKey.create(pkBytes), Falcon512PublicKey.create(pkBytes));
    assertEqualByValue(Falcon512PrivateKey.create(skBytes), Falcon512PrivateKey.create(skBytes));
    assertEqualByValue(Falcon512Signature.create(sigBytes), Falcon512Signature.create(sigBytes));

    final KeyPair other = falcon.generateNodeKeyPair();
    assertThat(keyPair.getPublicKey()).isNotEqualTo(other.getPublicKey());
    assertThat(keyPair.getPrivateKey()).isNotEqualTo(other.getPrivateKey());
  }

  @Test
  void privateKeyIsNotPrintable() {
    assertThat(falcon.generateNodeKeyPair().getPrivateKey().toString())
        .isEqualTo("Falcon512PrivateKey{<redacted>}");
  }

  @Test
  void keysOfTheWrongSizeAreRefused() {
    assertThatThrownBy(() -> Falcon512PublicKey.create(Bytes.wrap(new byte[897])))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("896");
    // The 1280-byte f || g || F form BouncyCastle emits lacks h and cannot sign on its own.
    assertThatThrownBy(() -> Falcon512PrivateKey.create(Bytes.wrap(new byte[1280])))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("2176");
  }

  @Test
  void fixedOffsetExtractionIsRefusedRatherThanSlicingGarbage() {
    // With no fixed signature length, Falcon cannot be cut out of a concatenation at a fixed
    // offset. Hybrids place it last and take the remainder (see Secp256k1Falcon512HybridTest).
    assertThatThrownBy(
            () ->
                new SignatureExtractor()
                    .extractSignatureBytesAtOffset(
                        Bytes.wrap(new byte[700]), 0, DSAParametersSet.FALCON512))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("FALCON512");
  }

  @Test
  void structuralValidityIsCappedAt752Bytes() {
    final SignatureValidationContext context = new SignatureValidationContext(true);
    final Signature genuine =
        falcon.sign(MESSAGE, falcon.generateNodeKeyPair().getPrivateKey());

    assertThat(genuine.isValid(context)).isTrue();
    assertThat(Falcon512Signature.create(Bytes.wrap(new byte[Falcon512Signature.MAX_LENGTH]))
            .isValid(context))
        .isTrue();
    assertThat(Falcon512Signature.create(Bytes.wrap(new byte[Falcon512Signature.MAX_LENGTH + 1]))
            .isValid(context))
        .isFalse();
    assertThat(Falcon512Signature.create(Bytes.EMPTY).isValid(context)).isFalse();
  }

  private static void assertEqualByValue(final Object a, final Object b) {
    assertThat(a).isNotSameAs(b).isEqualTo(b);
    assertThat(a.hashCode()).isEqualTo(b.hashCode());
  }

  private static PublicKey wrongLengthKey(final int length) {
    return new PublicKey() {
      private static final long serialVersionUID = 1L;

      @Override
      public String getAlgorithm() {
        return "FALCON512";
      }

      @Override
      public String getFormat() {
        return "RAW";
      }

      @Override
      public byte[] getEncoded() {
        return new byte[length];
      }
    };
  }
}
