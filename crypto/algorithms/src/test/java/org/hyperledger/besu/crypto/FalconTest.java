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

import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;
import org.hyperledger.besu.crypto.key.types.FalconPrivateKey;
import org.hyperledger.besu.crypto.key.types.FalconPublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureExtractor;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.crypto.signature.types.FalconSignature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Runs against every parameter set {@link Falcon} supports, so a parameter set added later is
 * covered automatically and any size still hard-coded for Falcon-512 fails here.
 */
class FalconTest {

  private static final Bytes MESSAGE = Bytes.fromHexString("0xdeadbeefcafebabe");

  static Stream<DSAParametersSet> falconParameterSets() {
    return Falcon.supportedParameterSets().stream();
  }

  @Test
  void everyFalconEntryInDsaParametersSetHasParameters() {
    // Adding a Falcon entry to DSAParametersSet without a row in Falcon's parameter table fails.
    final Set<DSAParametersSet> declared =
        Arrays.stream(DSAParametersSet.values())
            .filter(dsa -> dsa.getName().startsWith("FALCON"))
            .collect(Collectors.toSet());

    assertThat(Falcon.supportedParameterSets()).isEqualTo(declared).isNotEmpty();
  }

  @Test
  void falcon512SizesAreTheMeasuredOnes() {
    assertThat(DSAParametersSet.fromId((short) 0x0040)).isEqualTo(DSAParametersSet.FALCON512);
    assertThat(DSAParametersSet.FALCON512.getPublicKeyLength()).isEqualTo(896);
    assertThat(DSAParametersSet.FALCON512.getPrivateKeyLength()).isEqualTo(2176);
    assertThat(FalconSignature.maxLength(DSAParametersSet.FALCON512)).isEqualTo(752);
  }

  @Test
  void nonFalconParameterSetsAreRefused() {
    assertThatThrownBy(() -> new Falcon(DSAParametersSet.MLDSA44))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("MLDSA44");
    assertThatThrownBy(() -> FalconSignature.create(Bytes.of(1), DSAParametersSet.MLDSA44))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void parameterSetIsConsistent(final DSAParametersSet params) {
    final Falcon.Parameters parameters = Falcon.parametersFor(params);

    assertThat(
            parameters.fLength()
                + parameters.gLength()
                + parameters.capitalFLength()
                + params.getPublicKeyLength())
        .isEqualTo(params.getPrivateKeyLength());
    // Variable-length signatures: a fixed length would invite fixed-offset splitting.
    assertThat(params.getSignatureLength()).isNull();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void isNotRecoverableSoTransactionsMustCarryTheKey(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);

    assertThat(falcon).isNotInstanceOf(PublicKeyRecoverable.class);
    assertThat(falcon.getDsaParametersSet()).isEqualTo(params);
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void generatedKeysHaveTheDeclaredSizesAndThePublicKeyIsDerivableFromThePrivateKey(
      final DSAParametersSet params) {
    final KeyPair keyPair = new Falcon(params).generateNodeKeyPair();

    assertThat(keyPair.getPrivateKey().getEncoded()).hasSize(params.getPrivateKeyLength());
    assertThat(keyPair.getPublicKey().getEncoded()).hasSize(params.getPublicKeyLength());
    // KeyManager rebuilds a node public key from its private key file alone.
    assertThat(KeyFactory.createPublicKey(keyPair.getPrivateKey(), params))
        .isEqualTo(keyPair.getPublicKey());
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void signatureVerifies(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final KeyPair keyPair = falcon.generateNodeKeyPair();

    assertThat(
            falcon.verify(
                MESSAGE, falcon.sign(MESSAGE, keyPair.getPrivateKey()), keyPair.getPublicKey()))
        .isTrue();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void signatureOverDifferentDataIsRejected(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Signature signature = falcon.sign(MESSAGE, keyPair.getPrivateKey());

    assertThat(falcon.verify(Bytes.fromHexString("0x01"), signature, keyPair.getPublicKey()))
        .isFalse();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void signatureFromADifferentKeyIsRejected(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final KeyPair signer = falcon.generateNodeKeyPair();
    final KeyPair other = falcon.generateNodeKeyPair();
    final Signature signature = falcon.sign(MESSAGE, signer.getPrivateKey());

    assertThat(falcon.verify(MESSAGE, signature, other.getPublicKey())).isFalse();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void signaturesAreVariableLengthAndAllVerify(final DSAParametersSet params) {
    // The property that rules out any fixed-length assumption, such as hybrid concatenation.
    final Falcon falcon = new Falcon(params);
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

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void malformedInputFailsVerificationInsteadOfThrowing(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Signature genuine = falcon.sign(MESSAGE, keyPair.getPrivateKey());

    final Signature garbage =
        FalconSignature.create(Bytes.wrap(new byte[genuine.encodedBytes().size()]), params);
    final Signature truncated = FalconSignature.create(genuine.encodedBytes().slice(0, 10), params);
    final PublicKey shortKey = wrongLengthKey(params.getPublicKeyLength() - 1);

    assertThat(falcon.verify(MESSAGE, garbage, keyPair.getPublicKey())).isFalse();
    assertThat(falcon.verify(MESSAGE, truncated, keyPair.getPublicKey())).isFalse();
    assertThat(falcon.verify(MESSAGE, genuine, shortKey)).isFalse();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void keysSurviveAByteRoundTripThroughKeyFactory(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final KeyPair keyPair = falcon.generateNodeKeyPair();

    final PrivateKey reloadedSk =
        KeyFactory.createPrivateKey(
            Bytes.wrap(keyPair.getPrivateKey().getEncoded()),
            params,
            PrivateKeyRepresentation.EXPANDED,
            null);
    final PublicKey reloadedPk =
        KeyFactory.createPublicKey(Bytes.wrap(keyPair.getPublicKey().getEncoded()), params)
            .orElseThrow();

    assertThat(reloadedSk).isEqualTo(keyPair.getPrivateKey());
    assertThat(reloadedPk).isEqualTo(keyPair.getPublicKey());
    // A reloaded private key must still sign for the original public key.
    assertThat(falcon.verify(MESSAGE, falcon.sign(MESSAGE, reloadedSk), keyPair.getPublicKey()))
        .isTrue();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void signatureSurvivesAByteRoundTripThroughSignatureFactory(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final Signature signature = falcon.sign(MESSAGE, falcon.generateNodeKeyPair().getPrivateKey());

    final Signature decoded =
        SignatureFactory.createSignatureFromBytes(signature.encodedBytes(), params);

    assertThat(decoded).isInstanceOf(FalconSignature.class).isEqualTo(signature);
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void equalityIsByValueNotIdentity(final DSAParametersSet params) {
    final Falcon falcon = new Falcon(params);
    final KeyPair keyPair = falcon.generateNodeKeyPair();
    final Bytes pkBytes = Bytes.wrap(keyPair.getPublicKey().getEncoded());
    final Bytes skBytes = Bytes.wrap(keyPair.getPrivateKey().getEncoded());
    final Bytes sigBytes = falcon.sign(MESSAGE, keyPair.getPrivateKey()).encodedBytes();

    assertEqualByValue(
        FalconPublicKey.create(pkBytes, params), FalconPublicKey.create(pkBytes, params));
    assertEqualByValue(
        FalconPrivateKey.create(skBytes, params), FalconPrivateKey.create(skBytes, params));
    assertEqualByValue(
        FalconSignature.create(sigBytes, params), FalconSignature.create(sigBytes, params));

    final KeyPair other = falcon.generateNodeKeyPair();
    assertThat(keyPair.getPublicKey()).isNotEqualTo(other.getPublicKey());
    assertThat(keyPair.getPrivateKey()).isNotEqualTo(other.getPrivateKey());
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void privateKeyIsNotPrintable(final DSAParametersSet params) {
    assertThat(new Falcon(params).generateNodeKeyPair().getPrivateKey().toString())
        .isEqualTo("FalconPrivateKey{" + params.getName() + ", <redacted>}");
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void keysOfTheWrongSizeAreRefused(final DSAParametersSet params) {
    assertThatThrownBy(
            () ->
                FalconPublicKey.create(
                    Bytes.wrap(new byte[params.getPublicKeyLength() + 1]), params))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(String.valueOf(params.getPublicKeyLength()));
    // BouncyCastle's own f || g || F form lacks h and cannot sign on its own.
    final int bouncyCastleLength = params.getPrivateKeyLength() - params.getPublicKeyLength();
    assertThatThrownBy(
            () -> FalconPrivateKey.create(Bytes.wrap(new byte[bouncyCastleLength]), params))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(String.valueOf(params.getPrivateKeyLength()));
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void structuralValidityIsCappedAtTheMaximumLength(final DSAParametersSet params) {
    final SignatureValidationContext context = new SignatureValidationContext(true);
    final Falcon falcon = new Falcon(params);
    final Signature genuine = falcon.sign(MESSAGE, falcon.generateNodeKeyPair().getPrivateKey());
    final int max = FalconSignature.maxLength(params);

    assertThat(genuine.isValid(context)).isTrue();
    assertThat(FalconSignature.create(Bytes.wrap(new byte[max]), params).isValid(context)).isTrue();
    assertThat(FalconSignature.create(Bytes.wrap(new byte[max + 1]), params).isValid(context))
        .isFalse();
    assertThat(FalconSignature.create(Bytes.EMPTY, params).isValid(context)).isFalse();
  }

  @ParameterizedTest
  @MethodSource("falconParameterSets")
  void fixedOffsetExtractionIsRefusedRatherThanSlicingGarbage(final DSAParametersSet params) {
    // With no fixed signature length, Falcon cannot be cut out of a concatenation at a fixed
    // offset. Hybrids place it last and take the remainder (see Secp256k1Falcon512HybridTest).
    assertThatThrownBy(
            () ->
                new SignatureExtractor()
                    .extractSignatureBytesAtOffset(Bytes.wrap(new byte[700]), 0, params))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(params.getName());
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
        return "FALCON";
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
