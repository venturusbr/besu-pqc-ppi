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
package org.hyperledger.besu.crypto.key.types;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;

public class CompositePrivateKey implements PrivateKey {
  private final PrivateKey firstKey;
  private final PrivateKey secondKey;

  public CompositePrivateKey(final PrivateKey firstKey, final PrivateKey secondKey) {
    this.firstKey = firstKey;
    this.secondKey = secondKey;
  }

  public PrivateKey getFirstKey() {
    return firstKey;
  }

  public PrivateKey getSecondKey() {
    return secondKey;
  }

  @Override
  public String getAlgorithm() {
    return firstKey.getAlgorithm() + "-" + secondKey.getAlgorithm();
  }

  @Override
  public String getFormat() {
    return "concatenated";
  }

  @Override
  public byte[] getEncoded() {
    return Bytes.concatenate(Bytes.wrap(firstKey.getEncoded()), Bytes.wrap(secondKey.getEncoded()))
        .toArrayUnsafe();
  }

  public static CompositePrivateKey create(final PrivateKey firstSk, final PrivateKey secondSk) {
    return new CompositePrivateKey(firstSk, secondSk);
  }
}
