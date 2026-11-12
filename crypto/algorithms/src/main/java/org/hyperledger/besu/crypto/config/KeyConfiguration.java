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
package org.hyperledger.besu.crypto.config;

import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;

import java.io.File;

public class KeyConfiguration {
  private final File nodePrivateKeyFile;
  private final PrivateKeyRepresentation firstDSASkRepresentation;
  private final PrivateKeyRepresentation secondDSASkRepresentation;

  private KeyConfiguration(
      final PrivateKeyRepresentation firstDSASkRepresentation,
      final PrivateKeyRepresentation secondDSASKeyRepresentation,
      final File nodePrivateKeyFile) {
    this.firstDSASkRepresentation = firstDSASkRepresentation;
    this.secondDSASkRepresentation = secondDSASKeyRepresentation;
    this.nodePrivateKeyFile = nodePrivateKeyFile;
  }

  public static KeyConfiguration createSingleKeyConfig(
      final File nodePrivateKeyFile, final PrivateKeyRepresentation representation) {
    return new KeyConfiguration(representation, null, nodePrivateKeyFile);
  }

  // algoritmo híbrido — duas representações
  public static KeyConfiguration createHybridKeyConfig(
      final File nodePrivateKeyFile,
      final PrivateKeyRepresentation first,
      final PrivateKeyRepresentation second) {
    return new KeyConfiguration(first, second, nodePrivateKeyFile);
  }

  public boolean isHybrid() {
    return secondDSASkRepresentation != null;
  }

  public File getNodePrivateKeyFile() {
    return nodePrivateKeyFile;
  }

  public PrivateKeyRepresentation getFirstKeyRepresentation() {
    return firstDSASkRepresentation;
  }

  public PrivateKeyRepresentation getSecondKeyRepresentation() {
    return secondDSASkRepresentation;
  }
}
