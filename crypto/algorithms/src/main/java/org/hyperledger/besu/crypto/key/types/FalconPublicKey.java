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

import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;

/**
 * A Falcon public key: the polynomial {@code h} exactly as produced by BouncyCastle's {@code
 * FalconPublicKeyParameters.getH()}, without the one-byte header of the FIPS-style encoding. Its
 * length is the parameter set's {@link DSAParametersSet#getPublicKeyLength()}.
 */
public final class FalconPublicKey implements PublicKey {
  private static final long serialVersionUID = 1L;

  private final DSAParametersSet parametersSet;
  private final Bytes encoded;

  private FalconPublicKey(final DSAParametersSet parametersSet, final Bytes encoded) {
    this.parametersSet = parametersSet;
    this.encoded = encoded;
  }

  /**
   * Wraps an encoded public key.
   *
   * @param pkBytes the encoding of {@code h}
   * @param parametersSet the Falcon parameter set the key belongs to
   * @return the public key
   * @throws IllegalArgumentException if {@code parametersSet} is not a Falcon parameter set, or
   *     {@code pkBytes} is not its public key length
   */
  public static FalconPublicKey create(final Bytes pkBytes, final DSAParametersSet parametersSet) {
    Falcon.parametersFor(parametersSet);
    checkArgument(
        pkBytes.size() == parametersSet.getPublicKeyLength(),
        "%s public key must be %s bytes, got %s",
        parametersSet.getName(),
        parametersSet.getPublicKeyLength(),
        pkBytes.size());
    return new FalconPublicKey(parametersSet, pkBytes.copy());
  }

  /**
   * Derives the public key from a private key. Falcon's private key cannot regenerate {@code h}
   * through BouncyCastle's public API, so {@link FalconPrivateKey} carries it.
   *
   * @param sk a {@link FalconPrivateKey}
   * @return the corresponding public key
   */
  public static FalconPublicKey create(final PrivateKey sk) {
    checkArgument(
        sk instanceof FalconPrivateKey,
        "Expected a Falcon private key, got %s",
        sk == null ? null : sk.getClass().getName());
    final FalconPrivateKey falconSk = (FalconPrivateKey) sk;
    return new FalconPublicKey(falconSk.getParametersSet(), falconSk.getPublicKeyBytes());
  }

  /**
   * Gets the parameter set this key belongs to.
   *
   * @return the parameter set
   */
  public DSAParametersSet getParametersSet() {
    return parametersSet;
  }

  @Override
  public String getAlgorithm() {
    return parametersSet.getName();
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
    return o instanceof FalconPublicKey that
        && parametersSet == that.parametersSet
        && encoded.equals(that.encoded);
  }

  @Override
  public int hashCode() {
    return 31 * parametersSet.hashCode() + encoded.hashCode();
  }

  @Override
  public String toString() {
    return "FalconPublicKey{" + parametersSet.getName() + ", " + encoded.toHexString() + "}";
  }
}
