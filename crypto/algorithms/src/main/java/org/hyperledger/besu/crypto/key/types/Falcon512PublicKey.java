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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

/**
 * A Falcon-512 public key: the 896-byte polynomial {@code h} exactly as produced by BouncyCastle's
 * {@code FalconPublicKeyParameters.getH()}, without the one-byte header of the FIPS-style encoding.
 */
public final class Falcon512PublicKey implements PublicKey {
  private static final long serialVersionUID = 1L;

  /** Encoded length in bytes. */
  public static final int LENGTH = 896;

  private final Bytes encoded;

  private Falcon512PublicKey(final Bytes encoded) {
    this.encoded = encoded;
  }

  /**
   * Wraps an encoded public key.
   *
   * @param pkBytes the 896-byte encoding of {@code h}
   * @return the public key
   * @throws IllegalArgumentException if {@code pkBytes} is not exactly {@value #LENGTH} bytes
   */
  public static Falcon512PublicKey create(final Bytes pkBytes) {
    checkArgument(
        pkBytes.size() == LENGTH,
        "Falcon-512 public key must be %s bytes, got %s",
        LENGTH,
        pkBytes.size());
    return new Falcon512PublicKey(pkBytes.copy());
  }

  /**
   * Derives the public key from a private key. Falcon's private key cannot regenerate {@code h}
   * through BouncyCastle's public API, so {@link Falcon512PrivateKey} carries it.
   *
   * @param sk a {@link Falcon512PrivateKey}
   * @return the corresponding public key
   */
  public static Falcon512PublicKey create(final PrivateKey sk) {
    checkArgument(
        sk instanceof Falcon512PrivateKey,
        "Expected a Falcon-512 private key, got %s",
        sk == null ? null : sk.getClass().getName());
    return new Falcon512PublicKey(((Falcon512PrivateKey) sk).getPublicKeyBytes());
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
    return o instanceof Falcon512PublicKey that && encoded.equals(that.encoded);
  }

  @Override
  public int hashCode() {
    return encoded.hashCode();
  }

  @Override
  public String toString() {
    return "Falcon512PublicKey{" + encoded.toHexString() + "}";
  }
}
