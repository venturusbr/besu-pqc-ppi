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
package org.hyperledger.besu.crypto.keyexchange;

import java.util.Set;

public class KeyEstablishmentSchemeType {
  public static final String PLAIN = "PLAIN";
  public static final String TRADITIONAL_ECIES = "ECIES";
  public static final String PQ_TRADITIONAL_ECIES_MLKEM = "ECIES-MLKEM";

  public static final Set<String> NON_HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES =
      Set.of(TRADITIONAL_ECIES, PLAIN);
  public static final Set<String> HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES =
      Set.of(PQ_TRADITIONAL_ECIES_MLKEM);

  public static boolean schemeIsSupported(final String schemeName) {
    return NON_HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES.contains(schemeName)
        || HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES.contains(schemeName);
  }

  public static boolean isHybridScheme(final String schemeName) {
    return HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES.contains(schemeName);
  }
}
