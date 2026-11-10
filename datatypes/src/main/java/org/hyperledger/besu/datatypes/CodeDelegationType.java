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
package org.hyperledger.besu.datatypes;

import java.util.Optional;

public enum CodeDelegationType {
  LEGACY((byte) 0xf8),
  FLEXIBLE((byte) 0x01);

  private final byte serializedType;

  private static final CodeDelegationType[] codeDelegationTypeByOpaqueByte =
      new CodeDelegationType[256];

  CodeDelegationType(final byte serializedType) {
    this.serializedType = serializedType;
  }

  static {
    for (CodeDelegationType type : values()) {
      codeDelegationTypeByOpaqueByte[Byte.toUnsignedInt(type.getSerializedType())] = type;
    }
  }

  public byte getSerializedType() {
    return serializedType;
  }

  public static Optional<CodeDelegationType> fromOpaque(final byte opaqueByte) {
    try {
      return Optional.ofNullable(codeDelegationTypeByOpaqueByte[Byte.toUnsignedInt(opaqueByte)]);
    } catch (final ArrayIndexOutOfBoundsException e) {
      return Optional.empty();
    }
  }
}
