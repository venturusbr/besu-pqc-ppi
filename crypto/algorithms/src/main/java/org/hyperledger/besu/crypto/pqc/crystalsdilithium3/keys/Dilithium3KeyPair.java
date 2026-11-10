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
package org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public class Dilithium3KeyPair {
  private final Dilithium3PrivateKey privateKey;
  private final Dilithium3PublicKey publicKey;

  private Dilithium3KeyPair(
      final Dilithium3PrivateKey privateKey, final Dilithium3PublicKey publicKey) {
    checkNotNull(privateKey);
    checkNotNull(publicKey);
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public static Dilithium3KeyPair generateCrystalsDilithiumPair(
      final KeyPairGenerator keyPairGenerator, final DilithiumParameterSpec parameterSpec) {
    try {
      keyPairGenerator.initialize(parameterSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      PrivateKey privateKey = keyPair.getPrivate();
      PublicKey publicKey = keyPair.getPublic();

      byte[] privateKeyBytes = privateKey.getEncoded();
      byte[] publicKeyBytes = publicKey.getEncoded();

      return new Dilithium3KeyPair(
          Dilithium3PrivateKey.create(privateKeyBytes), Dilithium3PublicKey.create(publicKeyBytes));
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      return null;
    }
  }

  public static Dilithium3KeyPair createKeyPair(
      final Dilithium3PrivateKey privateKey, final Dilithium3PublicKey publicKey) {
    return new Dilithium3KeyPair(privateKey, publicKey);
  }

  public Dilithium3PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  public Dilithium3PublicKey getPublicKey() {
    return this.publicKey;
  }
}
