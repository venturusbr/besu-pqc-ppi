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

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Keys and signatures on SECP256K1 and SECP256R1 are handled by their own curve, whichever curve
 * the process-wide {@link SignatureAlgorithmFactory} was configured with. Every case runs with the
 * factory left at its SECP256K1 default and with it set to SECP256R1, as a genesis file's ecCurve
 * does.
 */
class SECPCurvesTest {

  // Private key 1: its public key is the curve's generator point.
  private static final Bytes32 KEY_ONE = Bytes32.fromHexStringLenient("0x01");
  private static final Bytes K1_GENERATOR =
      Bytes.fromHexString(
          "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  private static final Bytes R1_GENERATOR =
      Bytes.fromHexString(
          "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  // The well-known address of SECP256K1 private key 1.
  private static final Bytes K1_KEY_ONE_ADDRESS =
      Bytes.fromHexString("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");

  @AfterEach
  void resetFactory() {
    SignatureAlgorithmFactory.resetInstance();
  }

  static Stream<Arguments> curvesUnderEachConfiguredCurve() {
    return Stream.of(
        Arguments.of(DSAParametersSet.SECP256K1, "secp256k1"),
        Arguments.of(DSAParametersSet.SECP256K1, "secp256r1"),
        Arguments.of(DSAParametersSet.SECP256R1, "secp256k1"),
        Arguments.of(DSAParametersSet.SECP256R1, "secp256r1"));
  }

  private static SignatureAlgorithm configure(final String ecCurve) {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(SignatureAlgorithmType.create(ecCurve));
    return SignatureAlgorithmFactory.getInstance();
  }

  private static SignatureAlgorithm algorithmFor(final DSAParametersSet curve) {
    return curve == DSAParametersSet.SECP256K1 ? new SECP256K1() : new SECP256R1();
  }

  @ParameterizedTest(name = "{0} with the factory on {1}")
  @MethodSource("curvesUnderEachConfiguredCurve")
  void publicKeyIsDerivedOnTheKeysOwnCurve(final DSAParametersSet curve, final String ecCurve) {
    configure(ecCurve);
    final SECPPrivateKey privateKey = SECPPrivateKey.create(KEY_ONE, curve.getName());

    final PublicKey publicKey = KeyFactory.createPublicKey(privateKey, curve);

    assertThat(Bytes.wrap(publicKey.getEncoded()))
        .isEqualTo(curve == DSAParametersSet.SECP256K1 ? K1_GENERATOR : R1_GENERATOR);
  }

  @ParameterizedTest(name = "{0} with the factory on {1}")
  @MethodSource("curvesUnderEachConfiguredCurve")
  void nodeKeyPairIsConsistentAndLabelledWithItsCurve(
      final DSAParametersSet curve, final String ecCurve) {
    configure(ecCurve);
    final SignatureAlgorithm algorithm = algorithmFor(curve);

    final KeyPair keyPair = algorithm.generateNodeKeyPair();

    final SECPPrivateKey privateKey = (SECPPrivateKey) keyPair.getPrivateKey();
    assertThat(privateKey.getAlgorithm()).isEqualTo(curve.getName());
    assertThat(Bytes.wrap(keyPair.getPublicKey().getEncoded()))
        .isEqualTo(Bytes.wrap(algorithm.createPublicKey(privateKey).getEncoded()));
  }

  @ParameterizedTest(name = "{0} with the factory on {1}")
  @MethodSource("curvesUnderEachConfiguredCurve")
  void decodedSignatureVerifiesAndNamesItsCurve(
      final DSAParametersSet curve, final String ecCurve) {
    configure(ecCurve);
    final SignatureAlgorithm algorithm = algorithmFor(curve);
    final KeyPair keyPair = algorithm.generateKeyPair();
    final Bytes32 hash = Bytes32.random();
    final SECPSignature signature = algorithm.sign(hash, keyPair);

    final Signature decoded =
        SignatureFactory.createSignatureFromBytes(signature.encodedBytes(), curve);

    assertThat(decoded.getAlgorithm()).isEqualTo(curve.getName());
    assertThat(
            algorithm.verify(hash, (SECPSignature) decoded, (SECPPublicKey) keyPair.getPublicKey()))
        .isTrue();
  }

  @ParameterizedTest(name = "with the factory on {0}")
  @MethodSource("configuredCurves")
  void decodingRejectsValuesOutsideTheSecp256r1Order(final String ecCurve) {
    configure(ecCurve);
    final BigInteger r1Order = new SECP256R1().getCurve().getN();
    // Below SECP256K1's order, so only checking against R1's own order rejects it.
    final Bytes outOfRange = new SECPSignature(r1Order, BigInteger.ONE, (byte) 0).encodedBytes();

    assertThatThrownBy(
            () -> SignatureFactory.createSignatureFromBytes(outOfRange, DSAParametersSet.SECP256R1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest(name = "{0} with the factory on {1}")
  @MethodSource("curvesUnderEachConfiguredCurve")
  void malleabilityLimitIsHalfTheSignaturesOwnCurveOrder(
      final DSAParametersSet curve, final String ecCurve) {
    configure(ecCurve);
    final SignatureAlgorithm algorithm = algorithmFor(curve);
    final BigInteger halfOrder = algorithm.getHalfCurveOrder();
    final SignatureValidationContext disallowMalleability = new SignatureValidationContext(true);

    assertThat(
            algorithm
                .createSignature(BigInteger.ONE, halfOrder, (byte) 0)
                .isValid(disallowMalleability))
        .isTrue();
    assertThat(
            algorithm
                .createSignature(BigInteger.ONE, halfOrder.add(BigInteger.ONE), (byte) 0)
                .isValid(disallowMalleability))
        .isFalse();
  }

  @ParameterizedTest(name = "with the factory on {0}")
  @MethodSource("configuredCurves")
  void signatureOfUnstatedCurveKeepsItsFormerBehaviour(final String ecCurve) {
    final SignatureAlgorithm configured = configure(ecCurve);
    final BigInteger configuredHalfOrder = configured.getHalfCurveOrder();

    final SECPSignature atLimit = new SECPSignature(BigInteger.ONE, configuredHalfOrder, (byte) 0);
    final SECPSignature aboveLimit =
        new SECPSignature(BigInteger.ONE, configuredHalfOrder.add(BigInteger.ONE), (byte) 0);

    assertThat(atLimit.getAlgorithm()).isEqualTo(DSAParametersSet.SECP256K1.getName());
    assertThat(atLimit.isValid(new SignatureValidationContext(true))).isTrue();
    assertThat(aboveLimit.isValid(new SignatureValidationContext(true))).isFalse();
  }

  static Stream<String> configuredCurves() {
    return Stream.of("secp256k1", "secp256r1");
  }

  @Test
  void secp256k1KeyOneKeepsItsWellKnownAddress() {
    final SECPPrivateKey privateKey =
        SECPPrivateKey.create(KEY_ONE, DSAParametersSet.SECP256K1.getName());

    final PublicKey publicKey = KeyFactory.createPublicKey(privateKey, DSAParametersSet.SECP256K1);

    assertThat(Hash.keccak256(Bytes.wrap(publicKey.getEncoded())).slice(12))
        .isEqualTo(K1_KEY_ONE_ADDRESS);
  }

  @Test
  void theConfiguredInstanceIsUsedForItsOwnCurve() {
    final SignatureAlgorithm configured = configure("secp256r1");

    assertThat(SECPCurves.of(DSAParametersSet.SECP256R1)).isSameAs(configured);
    assertThat(SECPCurves.of(DSAParametersSet.SECP256K1)).isInstanceOf(SECP256K1.class);
  }

  @Test
  void postQuantumParametersAreNotACurve() {
    assertThatThrownBy(() -> SECPCurves.of(DSAParametersSet.MLDSA44))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest(name = "with the factory on {0}")
  @MethodSource("configuredCurves")
  void secp256r1IsSelectableAndItsSignerIsRecovered(final String ecCurve) {
    configure(ecCurve);
    final SupportedAlgorithms supported = new SupportedAlgorithms();
    assertThat(supported.supports(DSAParametersSet.SECP256R1.getName())).isTrue();
    final DigitalSignatureAlgorithm r1 =
        supported.getDSAByName(DSAParametersSet.SECP256R1.getName()).get();

    final KeyPair keyPair = r1.generateNodeKeyPair();
    final Bytes32 hash = Bytes32.random();
    final Signature signature = r1.sign(hash, keyPair.getPrivateKey());

    // As a transaction or consensus message signed with it would be checked: decoded from its
    // bytes, its signer recovered, then verified.
    final Signature decoded =
        SignatureFactory.createSignatureFromBytes(
            signature.encodedBytes(), DSAParametersSet.SECP256R1);
    final PublicKey recovered =
        PublicKeyHandler.resolvePublicKey(r1, decoded, Optional.empty(), hash).orElseThrow();
    assertThat(Bytes.wrap(recovered.getEncoded()))
        .isEqualTo(Bytes.wrap(keyPair.getPublicKey().getEncoded()));
    assertThat(r1.verify(hash, decoded, recovered)).isTrue();
  }
}
