/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECP256R1;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.GasLimitCalculator;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequest;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcErrorResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.RpcErrorType;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.MainnetTransactionValidator;
import org.hyperledger.besu.ethereum.mainnet.feemarket.FeeMarket;
import org.hyperledger.besu.evm.gascalculator.LondonGasCalculator;

import java.math.BigInteger;
import java.util.Optional;
import java.util.Set;
import java.util.stream.LongStream;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * On a network whose genesis sets ecCurve to secp256r1, a legacy EIP-1559 transaction signed with
 * secp256k1 often has no secp256r1 signer to recover. eth_sendRawTransaction must answer with the
 * usual invalid-signature error rather than fail internally.
 */
@ExtendWith(MockitoExtension.class)
class EthSendRawTransactionUnrecoverableSignatureTest {

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);
  private static final SECP256K1 K1 = new SECP256K1();
  private static final KeyPair K1_KEY_PAIR =
      K1.createKeyPair(
          K1.createPrivateKey(
              Bytes32.fromHexString(
                  "0x2222222222222222222222222222222222222222222222222222222222222222")));

  // The pool's own signature check, which is what rejects such a transaction.
  private final MainnetTransactionValidator validator =
      new MainnetTransactionValidator(
          new LondonGasCalculator(),
          GasLimitCalculator.constant(),
          FeeMarket.legacy(),
          true,
          Optional.of(CHAIN_ID),
          Set.of(TransactionType.FRONTIER, TransactionType.EIP1559),
          Set.of(BlobType.KZG_PROOF),
          Integer.MAX_VALUE);

  @Mock private TransactionPool transactionPool;

  @AfterEach
  void resetCurve() {
    SignatureAlgorithmFactory.resetInstance();
  }

  @Test
  void secp256k1SignatureWithNoSecp256r1SignerIsAnInvalidTransactionSignature() {
    when(transactionPool.addTransactionViaApi(any(Transaction.class)))
        .thenAnswer(
            invocation -> validator.validateTransactionSignature(invocation.getArgument(0)));
    final String rawTransaction = unrecoverableOnSecp256r1().toHexString();
    useSecp256r1Network();
    final JsonRpcRequestContext request =
        new JsonRpcRequestContext(
            new JsonRpcRequest("2.0", "eth_sendRawTransaction", new String[] {rawTransaction}));

    final JsonRpcResponse response = new EthSendRawTransaction(transactionPool).response(request);

    assertThat(response)
        .usingRecursiveComparison()
        .isEqualTo(
            new JsonRpcErrorResponse(
                request.getRequest().getId(), RpcErrorType.INVALID_TRANSACTION_SIGNATURE));
  }

  /**
   * A secp256k1-signed EIP-1559 transaction from which no secp256r1 key can be recovered. Signing
   * is deterministic, so the search is too; each nonce has about even odds.
   */
  private static Bytes unrecoverableOnSecp256r1() {
    return LongStream.range(0, 64)
        .mapToObj(EthSendRawTransactionUnrecoverableSignatureTest::signedWithSecp256k1)
        .filter(
            encoded -> {
              useSecp256r1Network();
              return Transaction.resolvableSender(
                      TransactionDecoder.decodeOpaqueBytes(
                          encoded, EncodingContext.POOLED_TRANSACTION))
                  .isEmpty();
            })
        .findFirst()
        .orElseThrow(() -> new AssertionError("no unrecoverable signature among 64 nonces"));
  }

  private static Bytes signedWithSecp256k1(final long nonce) {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(K1);
    final Transaction transaction =
        Transaction.builder()
            .type(TransactionType.EIP1559)
            .chainId(CHAIN_ID)
            .nonce(nonce)
            .maxPriorityFeePerGas(Wei.of(1))
            .maxFeePerGas(Wei.of(2))
            .gasLimit(21_000)
            .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
            .value(Wei.of(1))
            .payload(Bytes.EMPTY)
            .signAndBuild(K1_KEY_PAIR);
    return TransactionEncoder.encodeOpaqueBytes(transaction, EncodingContext.POOLED_TRANSACTION);
  }

  private static void useSecp256r1Network() {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(new NativeLikeSecp256r1());
  }

  /**
   * secp256r1 as its native library -- used wherever it is available, as on the nodes where this
   * was reported -- answers a signature with no signer: no key, rather than the exception of the
   * Java implementation used where the library is missing.
   */
  static final class NativeLikeSecp256r1 extends SECP256R1 {
    NativeLikeSecp256r1() {
      disableNative();
    }

    @Override
    protected BigInteger recoverFromSignature(
        final int recId, final BigInteger r, final BigInteger s, final Bytes32 dataHash) {
      try {
        return super.recoverFromSignature(recId, r, s, dataHash);
      } catch (final IllegalArgumentException e) {
        return null;
      }
    }
  }
}
