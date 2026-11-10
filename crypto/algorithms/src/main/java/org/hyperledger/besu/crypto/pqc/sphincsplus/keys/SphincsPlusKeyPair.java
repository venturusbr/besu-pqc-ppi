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
package org.hyperledger.besu.crypto.pqc.sphincsplus.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.crypto.SecureRandomProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

/** The SphincsPlus Key pair class. */
public class SphincsPlusKeyPair {

  private final SphincsPlusPrivateKey privateKey;
  private final SphincsPlusPublicKey publicKey;

  /**
   * Instantiates a new SphincsPlus Key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   */
  public SphincsPlusKeyPair(
      final SphincsPlusPrivateKey privateKey, final SphincsPlusPublicKey publicKey) {
    checkNotNull(privateKey);
    checkNotNull(publicKey);
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Create SphincsPlus key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   * @return the SphincsPlus key pair
   */
  public static SphincsPlusKeyPair createKeyPair(
      final SphincsPlusPrivateKey privateKey, final SphincsPlusPublicKey publicKey) {
    return new SphincsPlusKeyPair(privateKey, publicKey);
  }

  /**
   * Generate key pair.
   *
   * @param keyPairGenerator the key pair generator
   * @param sphincsPlusParameterSpec the SphincsPlus parameters
   * @return the SphincsPlus key pair
   */
  public static SphincsPlusKeyPair generate(
      final KeyPairGenerator keyPairGenerator,
      final SPHINCSPlusParameterSpec sphincsPlusParameterSpec) {
    try {
      keyPairGenerator.initialize(
          sphincsPlusParameterSpec, SecureRandomProvider.createSecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      PrivateKey privateKey = keyPair.getPrivate();
      PublicKey publicKey = keyPair.getPublic();

      byte[] privateKeySphincsPlusByte = privateKey.getEncoded();
      byte[] publicKeySphincsPlusByte = publicKey.getEncoded();

      return new SphincsPlusKeyPair(
          SphincsPlusPrivateKey.create(privateKeySphincsPlusByte),
          SphincsPlusPublicKey.create(publicKeySphincsPlusByte));
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Gets SphincsPlus private key.
   *
   * @return the private key
   */
  public SphincsPlusPrivateKey getPrivateKey() {
    return privateKey;
  }

  /**
   * Gets SphincsPlus public key.
   *
   * @return the public key
   */
  public SphincsPlusPublicKey getPublicKey() {
    return publicKey;
  }
}
