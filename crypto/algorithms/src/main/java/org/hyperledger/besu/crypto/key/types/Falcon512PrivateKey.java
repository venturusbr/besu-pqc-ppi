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
package org.hyperledger.besu.crypto.key.types;

import static com.google.common.base.Preconditions.checkArgument;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;

/**
 * A Falcon-512 private key, encoded as {@code f || g || F || h}.
 *
 * <p>This deliberately differs from BouncyCastle's {@code FalconPrivateKeyParameters.getEncoded()},
 * which is only {@code f || g || F} (1280 bytes). That form cannot be turned back into signing
 * parameters -- BouncyCastle's constructor requires the public key -- nor can the public key be
 * recomputed from it through the public API. Besu derives a node's public key from its private key
 * file ({@code KeyManager}, {@code KeyFactory.createKeyPair}), so the public key {@code h} is
 * appended, making the key self-sufficient.
 */
public final class Falcon512PrivateKey implements PrivateKey {
  private static final long serialVersionUID = 1L;

  private static final int F_LENGTH = 384;
  private static final int G_LENGTH = 384;
  private static final int CAPITAL_F_LENGTH = 512;

  /** Encoded length in bytes: {@code f}, {@code g}, {@code F} and {@code h}. */
  public static final int LENGTH =
      F_LENGTH + G_LENGTH + CAPITAL_F_LENGTH + Falcon512PublicKey.LENGTH;

  private final Bytes encoded;

  private Falcon512PrivateKey(final Bytes encoded) {
    this.encoded = encoded;
  }

  /**
   * Wraps an encoded private key.
   *
   * @param skBytes the {@value #LENGTH}-byte encoding {@code f || g || F || h}
   * @return the private key
   * @throws IllegalArgumentException if {@code skBytes} is not exactly {@value #LENGTH} bytes
   */
  public static Falcon512PrivateKey create(final Bytes skBytes) {
    checkArgument(
        skBytes.size() == LENGTH,
        "Falcon-512 private key must be %s bytes (f || g || F || h), got %s",
        LENGTH,
        skBytes.size());
    return new Falcon512PrivateKey(skBytes.copy());
  }

  /**
   * Captures BouncyCastle private key parameters, including the public key they carry.
   *
   * @param params the BouncyCastle parameters
   * @return the private key
   */
  public static Falcon512PrivateKey fromBouncyCastle(final FalconPrivateKeyParameters params) {
    return create(
        Bytes.concatenate(
            Bytes.wrap(params.getSpolyf()),
            Bytes.wrap(params.getG()),
            Bytes.wrap(params.getSpolyF()),
            Bytes.wrap(params.getPublicKey())));
  }

  /**
   * Rebuilds the BouncyCastle parameters needed for signing.
   *
   * @param parameters the BouncyCastle Falcon parameter set
   * @return the BouncyCastle private key parameters
   */
  public FalconPrivateKeyParameters toBouncyCastle(final FalconParameters parameters) {
    int offset = 0;
    final byte[] f = encoded.slice(offset, F_LENGTH).toArray();
    offset += F_LENGTH;
    final byte[] g = encoded.slice(offset, G_LENGTH).toArray();
    offset += G_LENGTH;
    final byte[] capitalF = encoded.slice(offset, CAPITAL_F_LENGTH).toArray();
    return new FalconPrivateKeyParameters(
        parameters, f, g, capitalF, getPublicKeyBytes().toArray());
  }

  Bytes getPublicKeyBytes() {
    return encoded.slice(LENGTH - Falcon512PublicKey.LENGTH, Falcon512PublicKey.LENGTH);
  }

  @Override
  public String getAlgorithm() {
    return DSAParametersSet.FALCON512.getName();
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    return encoded.toArray();
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    // Constant-time, so comparing secret material does not leak where two keys first differ.
    return o instanceof Falcon512PrivateKey that
        && MessageDigest.isEqual(encoded.toArrayUnsafe(), that.encoded.toArrayUnsafe());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encoded.toArrayUnsafe());
  }

  @Override
  public String toString() {
    return "Falcon512PrivateKey{<redacted>}";
  }
}
