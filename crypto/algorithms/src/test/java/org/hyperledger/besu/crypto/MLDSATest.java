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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;
import org.hyperledger.besu.crypto.signature.Signature;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class MLDSATest {

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testGenerateNodeKeyPair(final DSAParametersSet params) {
    MLDSA mldsa = new MLDSA(params);
    KeyPair keyPair = mldsa.generateNodeKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivateKey());
    assertNotNull(keyPair.getPublicKey());
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testSignAndVerify(final DSAParametersSet params) {
    MLDSA mldsa = new MLDSA(params);
    KeyPair keyPair = mldsa.generateNodeKeyPair();

    PrivateKey sk = keyPair.getPrivateKey();
    PublicKey pk = keyPair.getPublicKey();

    Bytes message = Bytes.wrap("test message".getBytes(UTF_8));

    Signature signature = mldsa.sign(message, sk);
    assertNotNull(signature);

    boolean isValid = mldsa.verify(message, signature, pk);
    assertTrue(isValid, "Signature should be valid");
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testVerifyFailsForModifiedMessage(final DSAParametersSet params) {
    MLDSA mldsa = new MLDSA(params);
    KeyPair keyPair = mldsa.generateNodeKeyPair();

    PrivateKey sk = keyPair.getPrivateKey();
    PublicKey pk = keyPair.getPublicKey();

    Bytes message = Bytes.wrap("test message".getBytes(UTF_8));
    Bytes modified = Bytes.wrap("modified message".getBytes(UTF_8));

    Signature signature = mldsa.sign(message, sk);

    boolean isValid = mldsa.verify(modified, signature, pk);
    assertFalse(isValid, "Signature shouldn't be valid for a modified message");
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testGetDsaParametersSet(final DSAParametersSet params) {
    MLDSA mldsa = new MLDSA(params);
    assertEquals(params, mldsa.getDsaParametersSet());
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testVerifyFailsForKeyOfWrongLengthInsteadOfThrowing(final DSAParametersSet params) {
    MLDSA mldsa = new MLDSA(params);
    KeyPair keyPair = mldsa.generateNodeKeyPair();

    Bytes message = Bytes.wrap("test message".getBytes(UTF_8));
    Signature signature = mldsa.sign(message, keyPair.getPrivateKey());

    // A 100-byte key used to reach BouncyCastle, which failed with an
    // ArrayIndexOutOfBoundsException while unpacking it.
    PublicKey shortKey = keyOfLength(100, params);

    assertFalse(
        mldsa.verify(message, signature, shortKey), "A key of the wrong length should not verify");
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testPublicKeyOfWrongLengthIsRefused(final DSAParametersSet params) {
    Bytes shortKey = Bytes.wrap(new byte[100]);

    IllegalArgumentException refused =
        assertThrows(IllegalArgumentException.class, () -> MLDSAPublicKey.create(shortKey, params));
    assertTrue(refused.getMessage().contains(String.valueOf(params.getPublicKeyLength())));
    assertThrows(
        IllegalArgumentException.class, () -> KeyFactory.createPublicKey(shortKey, params));
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testSignRefusesPrivateKeyOfAnotherParameterSet(final DSAParametersSet params) {
    DSAParametersSet other =
        params == DSAParametersSet.MLDSA44 ? DSAParametersSet.MLDSA65 : DSAParametersSet.MLDSA44;
    PrivateKey otherSk = new MLDSA(other).generateNodeKeyPair().getPrivateKey();

    assertSignRefused(params, otherSk);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testSignRefusesPrivateKeyOfWrongLength(final DSAParametersSet params) {
    // Neither the seed length (expanded by MLDSAPrivateKey.create) nor the expanded length, so the
    // bytes are kept as they are and used to reach BouncyCastle's key constructor.
    PrivateKey shortSk = MLDSAPrivateKey.create(Bytes.wrap(new byte[100]), params);

    assertSignRefused(params, shortSk);
  }

  @ParameterizedTest
  @EnumSource(
      value = DSAParametersSet.class,
      names = {"MLDSA44", "MLDSA65", "MLDSA87"})
  void testSignRefusesKeyOfAnotherTypeAndNull(final DSAParametersSet params) {
    PrivateKey falconSk =
        new Falcon(DSAParametersSet.FALCON512).generateNodeKeyPair().getPrivateKey();

    assertSignRefused(params, falconSk);
    assertSignRefused(params, null);
  }

  private static void assertSignRefused(final DSAParametersSet params, final PrivateKey sk) {
    Bytes message = Bytes.wrap("test message".getBytes(UTF_8));

    IllegalArgumentException refused =
        assertThrows(IllegalArgumentException.class, () -> new MLDSA(params).sign(message, sk));
    assertTrue(
        refused.getMessage().startsWith("Expected a " + params.getName() + " private key of "),
        refused.getMessage());
  }

  private static PublicKey keyOfLength(final int length, final DSAParametersSet params) {
    return new PublicKey() {
      private static final long serialVersionUID = 1L;

      @Override
      public String getAlgorithm() {
        return params.getName();
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
