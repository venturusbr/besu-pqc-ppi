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

import java.security.PrivateKey;
import java.security.PublicKey;

public class PqcKeyPair {
  private static PrivateKey privKey = null;
  private static PublicKey pubKey = null;

  public static void setKeys(final PrivateKey privateKey, final PublicKey publicKey) {
    if (privKey == null) {
      privKey = privateKey;
    }
    if (pubKey == null) {
      pubKey = publicKey;
    }
  }

  public static PrivateKey getPrivKey() {
    return privKey;
  }

  public static PublicKey getPubKey() {
    return pubKey;
  }
}
