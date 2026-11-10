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

public class PqcKeyPairSingleton {
  private static PqcKeyPair instance = null;

  private static PqcKeyPair createPqcKeypair(final String algorithmName) {
    System.out.println(algorithmName);
    PqcKeyPair keyPair = new PqcKeyPair();
    return keyPair;
  }

  public static PqcKeyPair getInstance(final String algorithmName) {
    if (instance == null) {
      instance = createPqcKeypair(algorithmName);
    }
    return instance;
  }
}
