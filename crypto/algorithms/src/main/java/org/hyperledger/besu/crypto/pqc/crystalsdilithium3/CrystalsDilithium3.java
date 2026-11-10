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
package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;

public class CrystalsDilithium3 extends AbstractCrystalsDilithium3 {
  @Override
  public String getAlgorithmName() {
    return "Dilithium";
  }

  @Override
  public String formatAlgorithmAndParameterTitle() {
    String parameterName =
        switch (SignatureAlgorithmFactory.getPqcParameterSpecIndex()) {
          case 0 -> "2";
          case 1 -> "3";
          case 2 -> "5";
          default -> "2";
        };
    return getAlgorithmName() + parameterName;
  }
}
