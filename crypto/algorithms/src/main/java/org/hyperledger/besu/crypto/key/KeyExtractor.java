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
package org.hyperledger.besu.crypto.key;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import org.apache.tuweni.bytes.Bytes;

public class KeyExtractor {
  public Bytes extractPrivateKeyBytesAtOffset(
      final Bytes keyBytes,
      final Integer fromIndex,
      final DSAParametersSet params,
      final PrivateKeyRepresentation representation) {

    return keyBytes.slice(fromIndex, privateKeyLength(params, representation));
  }

  /** The length of a private key of {@code params} in the given representation. */
  public Integer privateKeyLength(
      final DSAParametersSet params, final PrivateKeyRepresentation representation) {
    switch (representation) {
      case EXPANDED:
        return params.getPrivateKeyLength();
      case SEED:
        return params.getSeedLength();
      default:
        throw new IllegalArgumentException(
            "Unsupported private key representation: " + representation);
    }
  }

  public Bytes extractPublicKeyBytesAtOffset(
      final Bytes keyBytes, final Integer fromIndex, final DSAParametersSet params) {

    final Integer length = params.getPublicKeyLength();
    if (length == null || length <= 0) {
      throw new IllegalArgumentException("Public key length is invalid for " + params.getName());
    }

    return keyBytes.slice(fromIndex, length);
  }
}
