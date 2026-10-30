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
package org.hyperledger.besu.crypto;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Measures the CPU a node spends authenticating the signature of a flexible transaction, for every
 * {@link DSAParametersSet}, so the cost can be priced relative to a secp256k1 key recovery (the
 * 3000 gas of ECRECOVER). {@link SignatureGasReport} turns the results into gas.
 *
 * <p>Each signature is authenticated the way the node does it, and only that way: a recoverable
 * algorithm by recovering its key, any other algorithm by verifying against the provided key. A
 * hybrid is split into its halves and each half is authenticated by its own algorithm's rule, one
 * after the other, since gas prices the CPU used and not the wall-clock time of running the halves
 * in parallel. The first half is signed over the signing hash and the second over the hash followed
 * by the first signature, as in {@code HybridStrongNestingConcatenation}.
 *
 * <p>The verified-signature cache of the transaction validator is not involved: every call is the
 * cost paid by a node that sees the transaction for the first time.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(3)
public class SignatureCostBenchmark {

  /** Distinct keys, messages and signatures cycled through, so no single input is measured. */
  private static final int FIXTURES = 64;

  /** Without values, so JMH runs every constant of the enum and a new one is benchmarked too. */
  @Param
  public DSAParametersSet dsaType;

  private List<Operation> operations;
  private int next;

  /** Authenticates one half of a signature, or a whole non-hybrid signature. */
  private record Operation(List<Step> steps) {
    boolean run() {
      boolean ok = true;
      for (final Step step : steps) {
        ok &= step.run();
      }
      return ok;
    }
  }

  /** One recovery or one verification, with the inputs it needs already built. */
  private record Step(
      DigitalSignatureAlgorithm algorithm,
      Bytes32 recoveryHash,
      Bytes signedData,
      Signature signature,
      PublicKey publicKey) {

    boolean run() {
      if (algorithm instanceof PublicKeyRecoverable recoverable) {
        final Optional<PublicKey> recovered =
            recoverable.recoverPublicKeyFromSignature(recoveryHash, signature);
        return recovered.isPresent();
      }
      return algorithm.verify(signedData, signature, publicKey);
    }

    /** Whether the step authenticates the expected key, not just whether it returns something. */
    boolean authenticates() {
      if (algorithm instanceof PublicKeyRecoverable recoverable) {
        return recoverable
            .recoverPublicKeyFromSignature(recoveryHash, signature)
            .map(pk -> Bytes.wrap(pk.getEncoded()).equals(Bytes.wrap(publicKey.getEncoded())))
            .orElse(false);
      }
      return Boolean.TRUE.equals(algorithm.verify(signedData, signature, publicKey));
    }
  }

  @Setup(Level.Trial)
  public void setup() {
    final DigitalSignatureAlgorithm dsa =
        new SupportedAlgorithms().getDSAByName(dsaType.getName()).get();
    final Random random = new Random(dsaType.getId());

    operations = new ArrayList<>(FIXTURES);
    for (int i = 0; i < FIXTURES; i++) {
      final byte[] hash = new byte[32];
      random.nextBytes(hash);
      final Bytes32 signingHash = Bytes32.wrap(hash);

      final KeyPair keyPair = dsa.generateNodeKeyPair();
      final Signature signature = dsa.sign(signingHash, keyPair.getPrivateKey());

      final Operation operation = new Operation(steps(dsa, signingHash, signature, keyPair));
      for (final Step step : operation.steps()) {
        if (!step.authenticates()) {
          throw new IllegalStateException(
              "Fixture does not authenticate with "
                  + step.algorithm().getDsaParametersSet().getName()
                  + " in "
                  + dsaType.getName());
        }
      }
      operations.add(operation);
    }
  }

  private static List<Step> steps(
      final DigitalSignatureAlgorithm dsa,
      final Bytes32 signingHash,
      final Signature signature,
      final KeyPair keyPair) {
    if (dsa instanceof HybridDigitalSignatureAlgorithm hybrid) {
      final CompositeSignature composite = (CompositeSignature) signature;
      final CompositePublicKey compositeKey = (CompositePublicKey) keyPair.getPublicKey();
      final Signature first = composite.getFirstSignature();
      return List.of(
          new Step(
              hybrid.getFirstAlgorithm(),
              signingHash,
              signingHash,
              first,
              compositeKey.getFirstKey()),
          // Recovery, when the second half supports it, is over the signing hash as in
          // PublicKeyHandler; verification is over what that half actually signed.
          new Step(
              hybrid.getSecondAlgorithm(),
              signingHash,
              Bytes.concatenate(signingHash, first.encodedBytes()),
              composite.getSecondSignature(),
              compositeKey.getSecondKey()));
    }
    return List.of(new Step(dsa, signingHash, signingHash, signature, keyPair.getPublicKey()));
  }

  /** Recovers or verifies, per half, the signature of one transaction. */
  @Benchmark
  public boolean authenticate() {
    return operations.get(next++ & (FIXTURES - 1)).run();
  }
}
