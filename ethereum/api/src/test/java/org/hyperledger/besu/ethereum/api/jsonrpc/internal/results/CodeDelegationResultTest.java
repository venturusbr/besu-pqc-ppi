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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.results;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.ethereum.core.CodeDelegation;

import java.math.BigInteger;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * eth_getTransactionByHash reports each code delegation. Only a secp256k1 signature has yParity,
 * r and s; any other signature is reported whole, with no secp256k1 fields.
 */
class CodeDelegationResultTest {

  private static final Address DELEGATE =
      Address.fromHexString("0x000000000000000000000000000000000000beef");
  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Test
  void reportsAHybridDelegationWithoutSecp256k1Fields() {
    final DSAParametersSet hybrid = DSAParametersSet.SECP256K1MLDSA44;
    final DigitalSignatureAlgorithm dsa =
        new SupportedAlgorithms().getDSAByName(hybrid.getName()).get();
    final KeyPair signer = dsa.generateNodeKeyPair();
    final CodeDelegation delegation =
        new CodeDelegation(
            CodeDelegationType.FLEXIBLE,
            Optional.of(hybrid.getId()),
            BigInteger.ONE,
            DELEGATE,
            0L,
            Optional.of(((CompositePublicKey) signer.getPublicKey()).getSecondKey()),
            dsa.sign(Bytes32.ZERO, signer.getPrivateKey()));

    final JsonNode json = MAPPER.valueToTree(new CodeDelegationResult(delegation));

    assertThat(json.has("yParity")).isFalse();
    assertThat(json.has("r")).isFalse();
    assertThat(json.has("s")).isFalse();
    assertThat(json.get("dsaType").asText()).isEqualTo(String.valueOf(hybrid.getId()));
    assertThat(json.get("signature").asText())
        .isEqualTo(delegation.signature().encodedBytes().toString());
    assertThat(json.has("publicKey")).isTrue();
  }

  @Test
  void reportsALegacyDelegationWithSecp256k1Fields() {
    final KeyPair signer = SignatureAlgorithmFactory.getInstance().generateKeyPair();
    final org.hyperledger.besu.datatypes.CodeDelegation delegation =
        CodeDelegation.builder()
            .chainId(BigInteger.ONE)
            .address(DELEGATE)
            .nonce(0L)
            .signAndBuild(signer);

    final JsonNode json = MAPPER.valueToTree(new CodeDelegationResult(delegation));

    assertThat(json.has("yParity")).isTrue();
    assertThat(json.has("r")).isTrue();
    assertThat(json.has("s")).isTrue();
    assertThat(json.has("dsaType")).isFalse();
    assertThat(json.has("publicKey")).isFalse();
  }
}
