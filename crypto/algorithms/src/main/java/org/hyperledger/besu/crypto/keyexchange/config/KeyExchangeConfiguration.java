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
package org.hyperledger.besu.crypto.keyexchange.config;

import org.hyperledger.besu.crypto.keyexchange.KeyEstablishmentSchemeType;

public class KeyExchangeConfiguration {
  private boolean isHybridMode = false;
  private String handshakerType = KeyEstablishmentSchemeType.TRADITIONAL_ECIES;

  public static KeyExchangeConfiguration create() {
    return new KeyExchangeConfiguration();
  }

  public KeyExchangeConfiguration setHandshakerType(final String handshakerType) {
    if (KeyEstablishmentSchemeType.schemeIsSupported(handshakerType)) {
      this.handshakerType = handshakerType;
      setIsHybridMode();
    }
    return this;
  }

  private void setIsHybridMode() {
    this.isHybridMode = KeyEstablishmentSchemeType.isHybridScheme(handshakerType);
  }

  public boolean getIsHybridMode() {
    return isHybridMode;
  }

  public String getHandshakerType() {
    return handshakerType;
  }
}
