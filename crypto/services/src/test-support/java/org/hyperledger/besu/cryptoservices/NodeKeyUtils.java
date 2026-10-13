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

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.providers.NodeKeyProvider;
import org.hyperledger.besu.crypto.signature.Signature;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes32;

public class NodeKeyUtils {

  public static NodeKey createFrom(final KeyPair keyPair) {
    return new NodeKey(new SecurityModuleAdapter(new KeyPairSecurityModule(keyPair)));
  }

  public static NodeKey createFrom(final Bytes32 privateKey) {
    final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();
    final KeyPair keyPair =
        signatureAlgorithm.createKeyPair(signatureAlgorithm.createPrivateKey(privateKey));
    return new NodeKey(new SecurityModuleAdapter(new KeyPairSecurityModule(keyPair)));
  }

  /**
   * Generates a node key for the active algorithm, so tests that configure a post-quantum or hybrid
   * algorithm get node keys of that algorithm. Without one configured this is a SECP256K1 key, as
   * before.
   *
   * @return a new node key
   */
  public static NodeKey generate() {
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();
    if (dsa instanceof SignatureAlgorithm) {
      return new NodeKey(
          new SecurityModuleAdapter(
              new KeyPairSecurityModule(
                  SignatureAlgorithmFactory.getInstance().generateKeyPair())));
    }
    return createFrom(dsa, dsa.generateNodeKeyPair());
  }

  /**
   * Creates a node key that signs with any algorithm, including those {@link KeyPairSecurityModule}
   * cannot handle. It cannot perform an ECDH key agreement, which consensus tests do not need.
   *
   * @param dsa the algorithm to sign with
   * @param keyPair a key pair of that algorithm
   * @return the node key
   */
  public static NodeKey createFrom(final DigitalSignatureAlgorithm dsa, final KeyPair keyPair) {
    return new NodeKey(
        new NodeKeyProvider() {
          @Override
          public Signature sign(final Bytes32 data) {
            return dsa.sign(data, keyPair.getPrivateKey());
          }

          @Override
          public PublicKey getPublicKey() {
            return keyPair.getPublicKey();
          }

          @Override
          public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) {
            throw new UnsupportedOperationException(
                "ECDH key agreement is not supported by this test node key");
          }
        });
  }
}
