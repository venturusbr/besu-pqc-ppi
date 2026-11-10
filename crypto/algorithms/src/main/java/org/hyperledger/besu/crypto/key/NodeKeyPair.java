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

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.PrivateKey;
import java.security.PublicKey;

public class NodeKeyPair {
  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public NodeKeyPair(final PrivateKey sk, final PublicKey pk) {
    checkNotNull(sk);
    checkNotNull(pk);
    this.privateKey = sk;
    this.publicKey = pk;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }
}
