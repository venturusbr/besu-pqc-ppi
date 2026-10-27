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

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.pqc.metrics.MetricWriters;
import org.hyperledger.besu.crypto.signature.Signature;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class NodeKeyTest {

  @BeforeEach
  public void resetInstance() {
    SignatureAlgorithmFactory.resetInstance();
  }

  @Test
  public void publicKeyShouldMatch() {
    final Bytes keyPairPubKey =
        Bytes.fromHexString(
            "0x35f48529f73c4172850ed18997d00d101a9aebc130103c23d41d46351c1b1d72ffc8b246af3a446d99a8218bd69e231b75932ea9a79173751dc7eb2eb0e301f2");
    final Bytes32 keyPairPrvKey =
        Bytes32.fromHexString("0xf7a58d5e755d51fa2f6206e91dd574597c73248aaf946ec1964b8c6268d6207b");

    final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();
    final KeyPair keyPair =
        signatureAlgorithm.createKeyPair(signatureAlgorithm.createPrivateKey(keyPairPrvKey));
    final KeyPairSecurityModule keyPairSecurityModule = new KeyPairSecurityModule(keyPair);
    final NodeKey nodeKey = new NodeKey(new SecurityModuleAdapter(keyPairSecurityModule));

    Assertions.assertThat(Bytes.wrap(nodeKey.getPublicKey().getEncoded()))
        .isEqualByComparingTo(Bytes.wrap(keyPair.getPublicKey().getEncoded()));

    Assertions.assertThat(Bytes.wrap(nodeKey.getPublicKey().getEncoded()))
        .isEqualByComparingTo(keyPairPubKey);
  }

  @Test
  public void signMetricsLineHasTheColumnsOfTheHeader() {
    final NodeKey nodeKey = secp256k1NodeKey();
    final Signature signature = nodeKey.sign(HASH, "qbft-commit");

    final String line = NodeKey.signMetricsLine(1_234L, signature, "qbft-commit");

    final String[] header = MetricWriters.buildSignHeader().trim().split(",", -1);
    assertThat(line).endsWith("\n");
    assertThat(line.trim().split(",", -1))
        .hasSameSizeAs(header)
        .containsExactly("1234", DSAParametersSet.SECP256K1.getName(), "qbft-commit");
  }

  @Test
  public void signMetricsLineNamesAHybridAlgorithmAsItsParameterSet() {
    final DigitalSignatureAlgorithm hybrid =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName()).get();
    final KeyPair keyPair = hybrid.generateNodeKeyPair();
    final Signature signature = hybrid.sign(HASH, keyPair.getPrivateKey());

    final String line = NodeKey.signMetricsLine(1L, signature, "qbft-commit-seal");

    assertThat(line.trim().split(",", -1)[1])
        .isEqualTo(DSAParametersSet.SECP256K1MLDSA44.getName());
  }

  private static final Bytes32 HASH = Hash.keccak256(Bytes.fromHexString("0xc0ffee"));

  private static NodeKey secp256k1NodeKey() {
    final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();
    final KeyPair keyPair = signatureAlgorithm.generateKeyPair();
    return new NodeKey(new SecurityModuleAdapter(new KeyPairSecurityModule(keyPair)));
  }
}
