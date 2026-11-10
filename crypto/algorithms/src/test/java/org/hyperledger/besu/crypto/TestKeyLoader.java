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
package org.hyperledger.besu.crypto;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.util.List;

public final class TestKeyLoader {
  public static PrivateKey loadPrivateKey(
      final String resourcePath,
      final DSAParametersSet params,
      final PrivateKeyRepresentation skFirstRep,
      final PrivateKeyRepresentation skSecondRep)
      throws URISyntaxException {
    File skFile = new File(TestKeyLoader.class.getResource(resourcePath).toURI());

    KeyConfiguration keyConfig =
        skSecondRep == null
            ? KeyConfiguration.createSingleKeyConfig(skFile, skFirstRep)
            : KeyConfiguration.createHybridKeyConfig(skFile, skFirstRep, skSecondRep);

    KeyManager keyManager = new KeyManager(keyConfig);

    return keyManager.loadPrivateKeyFromFile(params);
  }

  public static String loadSeed(final String resourcePath) throws IOException, URISyntaxException {
    List<String> lines =
        Files.readAllLines(
            new File(TestKeyLoader.class.getResource(resourcePath).toURI()).toPath());
    if (lines.size() != 1) {
      throw new IllegalArgumentException("Seed inválida");
    }
    return lines.get(0);
  }

  public static String bytesToHex(final byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
