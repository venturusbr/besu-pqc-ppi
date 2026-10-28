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

import java.util.Collection;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.CommandLineOptionException;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Runs {@link SignatureCostBenchmark} for every algorithm in one JMH run and prices each one from
 * the secp256k1 key recovery in two ways:
 *
 * <pre>
 * gas (relative) = ECRECOVER_GAS * time(algorithm) / time(secp256k1)
 * gas (absolute) = gas(secp256k1) * time(algorithm) / time(secp256k1),
 *                  where gas(secp256k1) = time(secp256k1) * GAS_PER_SECOND
 * </pre>
 *
 * <p>The relative column anchors secp256k1 at the 3000 gas Ethereum already charges for it, so it
 * does not depend on the machine. The absolute column anchors it at its measured time, converted
 * with the 100 Mgas/s target that Besu's evmtool uses to derive gas from execution time; it equals
 * time(algorithm) * GAS_PER_SECOND and so depends on the machine.
 *
 * <p>All algorithms are measured in the same run, so load on the machine affects the baseline and
 * the algorithm alike and mostly cancels out in the ratio. The conservative column takes the upper
 * end of the algorithm's error interval over the lower end of the baseline's, as a bound to round
 * the relative gas up to.
 */
public class SignatureGasReport {

  /** Gas of the ECRECOVER precompile, taken as the price of one secp256k1 key recovery. */
  static final long ECRECOVER_GAS = 3_000L;

  /** The 100 Mgas/s target of Besu's evmtool benchmarks (BenchmarkExecutor): 1 gas = 10 ns. */
  static final long GAS_PER_SECOND = 100_000_000L;

  private static final double MICROSECONDS_PER_SECOND = 1_000_000D;

  /**
   * Runs the benchmark and prints the gas table.
   *
   * @param args JMH command-line options, e.g. {@code -p dsaType=SECP256K1,MLDSA87} to measure only
   *     some algorithms; the secp256k1 baseline must be among them
   * @throws RunnerException if JMH fails to run
   * @throws CommandLineOptionException if the options cannot be parsed
   */
  public static void main(final String[] args)
      throws RunnerException, CommandLineOptionException {
    final Options options =
        new OptionsBuilder()
            .parent(new CommandLineOptions(args))
            .include(SignatureCostBenchmark.class.getName())
            // the absolute column converts the score from microseconds to seconds
            .timeUnit(TimeUnit.MICROSECONDS)
            .build();
    final Collection<RunResult> results = new Runner(options).run();

    final Map<DSAParametersSet, Result<?>> byType = new EnumMap<>(DSAParametersSet.class);
    for (final RunResult result : results) {
      byType.put(
          DSAParametersSet.valueOf(result.getParams().getParam("dsaType")),
          result.getPrimaryResult());
    }

    final Result<?> baseline = byType.get(DSAParametersSet.SECP256K1);
    if (baseline == null) {
      throw new IllegalStateException("The secp256k1 baseline was not measured");
    }

    final double baselineAbsoluteGas =
        baseline.getScore() / MICROSECONDS_PER_SECOND * GAS_PER_SECOND;

    System.out.println();
    System.out.printf(
        "gas (relative) = %,d gas x time / time(SECP256K1), anchored at ECRECOVER%n",
        ECRECOVER_GAS);
    System.out.printf(
        "gas (absolute) = %,.0f gas x time / time(SECP256K1), where %,.0f gas = %.3f %s x %,d gas/s"
            + " (100 Mgas/s, 1 gas = 10 ns)%n",
        baselineAbsoluteGas,
        baselineAbsoluteGas,
        baseline.getScore(),
        baseline.getScoreUnit(),
        GAS_PER_SECOND);
    System.out.println();
    System.out.printf(
        "%-22s %12s %10s %7s %15s %15s %15s%n",
        "dsaType",
        "time (" + baseline.getScoreUnit() + ")",
        "± error",
        "ratio",
        "gas (relative)",
        "conserv. (rel.)",
        "gas (absolute)");
    for (final Map.Entry<DSAParametersSet, Result<?>> entry : byType.entrySet()) {
      final Result<?> result = entry.getValue();
      final double ratio = result.getScore() / baseline.getScore();
      final double conservativeRatio =
          (result.getScore() + error(result)) / (baseline.getScore() - error(baseline));
      System.out.printf(
          "%-22s %12.3f %10.3f %7.2f %,15d %,15d %,15d%n",
          entry.getKey().getName(),
          result.getScore(),
          error(result),
          ratio,
          (long) Math.ceil(ECRECOVER_GAS * ratio),
          (long) Math.ceil(ECRECOVER_GAS * conservativeRatio),
          (long) Math.ceil(baselineAbsoluteGas * ratio));
    }

    // JMH drops every result of a parameter whose fork failed, so say which ones are missing
    // rather than leave them out of the table without a word.
    for (final DSAParametersSet dsaType : DSAParametersSet.values()) {
      if (!byType.containsKey(dsaType)) {
        System.out.printf("%-22s %14s%n", dsaType.getName(), "no result");
      }
    }
  }

  /** The half-width of the 99.9% confidence interval, or zero when it could not be computed. */
  private static double error(final Result<?> result) {
    final double error = result.getScoreError();
    return Double.isNaN(error) ? 0 : error;
  }
}
