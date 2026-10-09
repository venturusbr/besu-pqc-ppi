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

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.api.query.TransactionWithMetadata;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A flexible transaction signed with SECP256K1 carries no public key, since the key is recovered
 * from its signature. It has to encode, decode and be reported over RPC without one.
 */
class FlexibleSecp256k1TransactionResultTest {

  private static final short SECP256K1_ID = DSAParametersSet.SECP256K1.getId();
  private static final SignatureAlgorithm SECP = SignatureAlgorithmFactory.getInstance();

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    config.buildAccountSupportedAlgorithms(List.of(DSAParametersSet.SECP256K1));
    DSAProviderFactory.setDsaProvider(config, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void survivesTheWireWithoutAPublicKey() {
    final KeyPair keyPair = SECP.generateKeyPair();
    final Transaction signed = sign(keyPair);

    final Transaction decoded =
        TransactionDecoder.decodeOpaqueBytes(
            TransactionEncoder.encodeOpaqueBytes(signed, EncodingContext.BLOCK_BODY),
            EncodingContext.BLOCK_BODY);

    assertThat(decoded.getType()).isEqualTo(TransactionType.FLEXIBLE_EIP1559);
    assertThat(decoded.getMaybePublicKey()).isEmpty();
    assertThat(decoded.getHash()).isEqualTo(signed.getHash());
    assertThat(decoded.getSender()).isEqualTo(Address.extract(keyPair.getPublicKey()));
  }

  @Test
  void isReportedOverRpcWithoutAPublicKey() {
    final Transaction signed = sign(SECP.generateKeyPair());

    final JsonNode json =
        new ObjectMapper()
            .valueToTree(
                new TransactionCompleteResult(
                    new TransactionWithMetadata(
                        signed, 1L, Optional.of(Wei.ONE), Hash.ZERO, 0)));

    assertThat(json.has("publicKey")).isFalse();
    assertThat(json.get("signature").asText())
        .isEqualTo(signed.getSignature().encodedBytes().toHexString());
  }

  private static Transaction sign(final KeyPair keyPair) {
    // The signing hash covers every field but the signature, so a placeholder is enough to read it.
    final Bytes32 signingHash =
        unsigned().signature(SECP.sign(Bytes32.ZERO, keyPair)).build().getSigningHash();
    final Signature signature = SECP.sign(signingHash, keyPair);
    return unsigned().signature(signature).build();
  }

  private static Transaction.Builder unsigned() {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(SECP256K1_ID)
        .chainId(BigInteger.valueOf(1337))
        .nonce(7)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(2))
        .gasLimit(21_000)
        .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
        .value(Wei.of(1_000))
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(Optional.empty());
  }
}
