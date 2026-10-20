/*
 * Copyright ConsenSys AG.
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
package org.hyperledger.besu.cryptoservices;

import org.hyperledger.besu.crypto.pqc.metrics.CSVWriter;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.providers.NodeKeyProvider;
import org.hyperledger.besu.crypto.signature.Signature;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes32;
/** The Node key. */
public class NodeKey {
  private final NodeKeyProvider nodeKeyProvider;
  private final CSVWriter signWriter;

  /**
   * Instantiates a new Node key.
   *
   * @param nodeKeyProvider the key provider.
   */
  public NodeKey(final NodeKeyProvider nodeKeyProvider) {
    this.nodeKeyProvider = nodeKeyProvider;
    this.signWriter = MetricWriters.getSignInstance();
  }

  /**
   * Sign hash and get secp signature.
   *
   * @param dataHash the data hash
   * @return the secp signature
   */
  public Signature sign(final Bytes32 dataHash, final String finality) {

    long startSign = System.nanoTime();
    Signature signature = nodeKeyProvider.sign(dataHash);
    long endSign = System.nanoTime();
    
    writeSignMetrics(startSign, endSign, finality, signature.encodedBytes().size());

    return signature;
  }

  /**
   * Gets public key.
   *
   * @return the public key
   */
  public PublicKey getPublicKey() {
    return nodeKeyProvider.getPublicKey();
  }


  /**
   * Calculate ecdh key agreement.
   *
   * @param partyKey the party key
   * @return the bytes32
   */
  public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
    return nodeKeyProvider.calculateECDHKeyAgreement(partyKey);
  }

  private void writeSignMetrics(final long startTime, final long endTime, final String finality, final Integer signatureLength){
    // The node key signs from several threads at once, so the line is built locally rather than
    // in a builder shared by all of them.
    long totalTime = endTime - startTime;
    signWriter.write(totalTime + "," + signatureLength + "," + finality + "\n");
  }
}
