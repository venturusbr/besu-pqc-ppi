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
package org.hyperledger.besu.ethereum.mainnet;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECP256R1;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.GasLimitCalculator;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;
import org.hyperledger.besu.ethereum.mainnet.feemarket.FeeMarket;
import org.hyperledger.besu.ethereum.transaction.TransactionInvalidReason;
import org.hyperledger.besu.evm.gascalculator.LondonGasCalculator;

import java.math.BigInteger;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A legacy transaction carries no algorithm id, so its signer is recovered on the network's curve.
 * On a network whose genesis sets ecCurve to secp256r1, a transaction signed with secp256k1 has an
 * r that, for about half of all signatures, is not the x-coordinate of any secp256r1 point: no key
 * can be recovered, and the transaction must be rejected as an invalid signature.
 *
 * <p>The two secp256r1 implementations report this differently. The native library, which Besu uses
 * wherever it is available, recovers no key; the Java implementation, used where it is not, throws
 * on the invalid point. Both must end in the same rejection.
 */
class UnrecoverableSignatureTest {

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);
  private static final SECP256K1 K1 = new SECP256K1();
  private static final KeyPair K1_KEY_PAIR =
      K1.createKeyPair(
          K1.createPrivateKey(
              Bytes32.fromHexString(
                  "0x1111111111111111111111111111111111111111111111111111111111111111")));

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

  @AfterEach
  void resetCurve() {
    SignatureAlgorithmFactory.resetInstance();
  }

  static Stream<Arguments> secp256r1Implementations() {
    return Stream.of(
        Arguments.of("native library", (Supplier<SignatureAlgorithm>) NativeLikeSecp256r1::new),
        Arguments.of(
            "Java implementation",
            (Supplier<SignatureAlgorithm>) UnrecoverableSignatureTest::java));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("secp256r1Implementations")
  void secp256k1SignatureWithNoSecp256r1SignerIsAnInvalidSignature(
      final String implementation, final Supplier<SignatureAlgorithm> secp256r1) {
    final Transaction received =
        receivedOnSecp256r1Network(secp256r1, tx -> Transaction.resolvableSender(tx).isEmpty());

    final ValidationResult<TransactionInvalidReason> result =
        validator.validateTransactionSignature(received);

    assertThat(result.isValid()).isFalse();
    assertThat(result.getInvalidReason()).isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
    assertThat(result.getErrorMessage())
        .isEqualTo("sender could not be extracted from transaction signature");
  }

  @Test
  void aSignerThatCannotBeRecoveredIsOnlyTriedOnce() {
    final NativeLikeSecp256r1 secp256r1 = new NativeLikeSecp256r1();
    final Transaction received =
        receivedOnSecp256r1Network(
            () -> secp256r1, tx -> Transaction.resolvableSender(tx).isEmpty());
    secp256r1.recoveries.set(0);

    // What a remote batch goes through: sorting and the priority check look the sender up, then
    // validation, then the pool's log.
    for (int i = 0; i < 10; i++) {
      assertThat(Transaction.resolvableSender(received)).isEmpty();
    }
    assertThat(validator.validateTransactionSignature(received).getInvalidReason())
        .isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
    assertThat(received.toString()).contains("sender=unknown");

    assertThat(secp256r1.recoveries).hasValue(0);
  }

  /**
   * Documents what recovery cannot detect: when r does land on secp256r1, a key is "recovered" and
   * the signature checks out against it, so the transaction is attributed to an unrelated account.
   * Only signing with the network's curve avoids this.
   */
  @Test
  void secp256k1SignatureThatLandsOnSecp256r1IsAttributedToAnUnrelatedSender() {
    final Transaction received =
        receivedOnSecp256r1Network(
            UnrecoverableSignatureTest::java, tx -> Transaction.resolvableSender(tx).isPresent());

    assertThat(validator.validateTransactionSignature(received).isValid()).isTrue();
    assertThat(received.getSender()).isNotEqualTo(Address.extract(K1_KEY_PAIR.getPublicKey()));
  }

  /**
   * Signs EIP-1559 transactions with secp256k1, then decodes them on a secp256r1 network as {@code
   * eth_sendRawTransaction} does, until one matches. Signing is deterministic, so the search is
   * too; each nonce has about even odds either way.
   */
  private static Transaction receivedOnSecp256r1Network(
      final Supplier<SignatureAlgorithm> secp256r1, final Predicate<Transaction> wanted) {
    return LongStream.range(0, 64)
        .mapToObj(UnrecoverableSignatureTest::signedWithSecp256k1)
        .map(encoded -> decodedOnSecp256r1Network(encoded, secp256r1.get()))
        .filter(wanted)
        .findFirst()
        .orElseThrow(() -> new AssertionError("no matching signature among 64 nonces"));
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

  private static Transaction decodedOnSecp256r1Network(
      final Bytes encoded, final SignatureAlgorithm secp256r1) {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(secp256r1);
    return TransactionDecoder.decodeOpaqueBytes(encoded, EncodingContext.POOLED_TRANSACTION);
  }

  private static SignatureAlgorithm java() {
    final SECP256R1 secp256r1 = new SECP256R1();
    secp256r1.disableNative();
    return secp256r1;
  }

  /**
   * secp256r1 as its native library answers a signature with no signer: no key, rather than the
   * Java implementation's exception. Lets this behaviour be tested where the library is missing.
   */
  static final class NativeLikeSecp256r1 extends SECP256R1 {
    final AtomicInteger recoveries = new AtomicInteger();

    NativeLikeSecp256r1() {
      disableNative();
    }

    @Override
    protected BigInteger recoverFromSignature(
        final int recId, final BigInteger r, final BigInteger s, final Bytes32 dataHash) {
      recoveries.incrementAndGet();
      try {
        return super.recoverFromSignature(recId, r, s, dataHash);
      } catch (final IllegalArgumentException e) {
        return null;
      }
    }
  }
}
