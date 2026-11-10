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
package org.hyperledger.besu.crypto.pqc.falcon.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.crypto.SecureRandomProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public class FalconKeyPair {

  private final FalconPrivateKey privateKey;
  private final FalconPublicKey publicKey;

  /**
   * Instantiates a new Falcon Key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   */
  public FalconKeyPair(final FalconPrivateKey privateKey, final FalconPublicKey publicKey) {
    checkNotNull(privateKey);
    checkNotNull(publicKey);
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Create Falcon key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   * @return the Falcon key pair
   */
  public static FalconKeyPair createKeyPair(
      final FalconPrivateKey privateKey, final FalconPublicKey publicKey) {
    return new FalconKeyPair(privateKey, publicKey);
  }

  /**
   * Generate Falcon key pair.
   *
   * @param keyPairGenerator the key pair generator
   * @param falconParameterSpec the Falcon parameters
   * @return the Falcon key pair
   */
  public static FalconKeyPair generate(
      final KeyPairGenerator keyPairGenerator, final FalconParameterSpec falconParameterSpec) {
    try {
      keyPairGenerator.initialize(falconParameterSpec, SecureRandomProvider.createSecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      PrivateKey privateKey = keyPair.getPrivate();
      PublicKey publicKey = keyPair.getPublic();

      byte[] privateKeySphincsPlusByte = privateKey.getEncoded();
      byte[] publicKeySphincsPlusByte = publicKey.getEncoded();

      return new FalconKeyPair(
          FalconPrivateKey.create(privateKeySphincsPlusByte),
          FalconPublicKey.create(publicKeySphincsPlusByte));
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Gets Falcon private key.
   *
   * @return the private key
   */
  public FalconPrivateKey getPrivateKey() {
    return privateKey;
  }

  /**
   * Gets Falcon public key.
   *
   * @return the public key
   */
  public FalconPublicKey getPublicKey() {
    return publicKey;
  }
}
