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

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;

/**
 * A Falcon private key, encoded as {@code f || g || F || h}. Its length is the parameter set's
 * {@link DSAParametersSet#getPrivateKeyLength()}; the component lengths come from {@link
 * Falcon#parametersFor}.
 *
 * <p>This deliberately differs from BouncyCastle's {@code FalconPrivateKeyParameters.getEncoded()},
 * which is only {@code f || g || F}. That form cannot be turned back into signing parameters --
 * BouncyCastle's constructor requires the public key -- nor can the public key be recomputed from
 * it through the public API. Besu derives a node's public key from its private key file ({@code
 * KeyManager}, {@code KeyFactory.createKeyPair}), so the public key {@code h} is appended, making
 * the key self-sufficient.
 */
public final class FalconPrivateKey implements PrivateKey {
  private static final long serialVersionUID = 1L;

  private final DSAParametersSet parametersSet;
  private final Bytes encoded;

  private FalconPrivateKey(final DSAParametersSet parametersSet, final Bytes encoded) {
    this.parametersSet = parametersSet;
    this.encoded = encoded;
  }

  /**
   * Wraps an encoded private key.
   *
   * @param skBytes the encoding {@code f || g || F || h}
   * @param parametersSet the Falcon parameter set the key belongs to
   * @return the private key
   * @throws IllegalArgumentException if {@code parametersSet} is not a Falcon parameter set, or
   *     {@code skBytes} is not its private key length
   */
  public static FalconPrivateKey create(final Bytes skBytes, final DSAParametersSet parametersSet) {
    final Falcon.Parameters parameters = Falcon.parametersFor(parametersSet);
    final int expected =
        parameters.fLength()
            + parameters.gLength()
            + parameters.capitalFLength()
            + parametersSet.getPublicKeyLength();
    checkArgument(
        expected == parametersSet.getPrivateKeyLength(),
        "Inconsistent %s sizes: components add up to %s but the private key length is %s",
        parametersSet.getName(),
        expected,
        parametersSet.getPrivateKeyLength());
    checkArgument(
        skBytes.size() == expected,
        "%s private key must be %s bytes (f || g || F || h), got %s",
        parametersSet.getName(),
        expected,
        skBytes.size());
    return new FalconPrivateKey(parametersSet, skBytes.copy());
  }

  /**
   * Captures BouncyCastle private key parameters, including the public key they carry.
   *
   * @param params the BouncyCastle parameters
   * @param parametersSet the Falcon parameter set they belong to
   * @return the private key
   */
  public static FalconPrivateKey fromBouncyCastle(
      final FalconPrivateKeyParameters params, final DSAParametersSet parametersSet) {
    return create(
        Bytes.concatenate(
            Bytes.wrap(params.getSpolyf()),
            Bytes.wrap(params.getG()),
            Bytes.wrap(params.getSpolyF()),
            Bytes.wrap(params.getPublicKey())),
        parametersSet);
  }

  /**
   * Rebuilds the BouncyCastle parameters needed for signing.
   *
   * @return the BouncyCastle private key parameters
   */
  public FalconPrivateKeyParameters toBouncyCastle() {
    final Falcon.Parameters parameters = Falcon.parametersFor(parametersSet);
    int offset = 0;
    final byte[] f = encoded.slice(offset, parameters.fLength()).toArray();
    offset += parameters.fLength();
    final byte[] g = encoded.slice(offset, parameters.gLength()).toArray();
    offset += parameters.gLength();
    final byte[] capitalF = encoded.slice(offset, parameters.capitalFLength()).toArray();
    return new FalconPrivateKeyParameters(
        parameters.bouncyCastle(), f, g, capitalF, getPublicKeyBytes().toArray());
  }

  /**
   * Gets the parameter set this key belongs to.
   *
   * @return the parameter set
   */
  public DSAParametersSet getParametersSet() {
    return parametersSet;
  }

  Bytes getPublicKeyBytes() {
    final int pkLength = parametersSet.getPublicKeyLength();
    return encoded.slice(encoded.size() - pkLength, pkLength);
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
    // Constant-time, so comparing secret material does not leak where two keys first differ.
    return o instanceof FalconPrivateKey that
        && parametersSet == that.parametersSet
        && MessageDigest.isEqual(encoded.toArrayUnsafe(), that.encoded.toArrayUnsafe());
  }

  @Override
  public int hashCode() {
    return 31 * parametersSet.hashCode() + Arrays.hashCode(encoded.toArrayUnsafe());
  }

  @Override
  public String toString() {
    return "FalconPrivateKey{" + parametersSet.getName() + ", <redacted>}";
  }
}
