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
package org.hyperledger.besu.crypto.pqc.keys;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public abstract class PqcPrivateKey implements java.security.PrivateKey {
  private final byte[] encoded;

  protected PqcPrivateKey(final byte[] encoded) {
    checkNotNull(encoded);
    this.encoded = encoded;
  }

  @Override
  public byte[] getEncoded() {
    return encoded;
  }

  @Override
  public abstract String getAlgorithm();

  @Override
  public String getFormat() {
    return null;
  }

  public String bytesToHex() {
    StringBuilder result = new StringBuilder();
    for (byte b : encoded) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
    return result.toString();
  }

  public static byte[] hexToBytes(final String hex) {
    byte[] encoded = new BigInteger(hex, 16).toByteArray();
    return encoded;
  }

  public PrivateKey getPrivateKeyFromEncoded() {
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("wip", "BCPQC");
      return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }
}
