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
package org.hyperledger.besu.consensus.common.bft.inttest;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.consensus.common.bft.messagewrappers.BftMessage;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockHeader;

import java.util.Objects;

import org.apache.tuweni.bytes.Bytes;

/** Compares the consensus message a node sent with the one a test expected it to send. */
public class BftMessageAssertions {

  /*
   * Fields holding a signature, or the key that travels with one. Signatures of the post-quantum
   * algorithms are randomized, so the same message signed twice differs here; the key differs in
   * form too, a hybrid's sent message carrying only the half that cannot be recovered.
   */
  private static final String SIGNATURE_FIELDS = "(.*\\.)?(signature|publicKey|commitSeal)";

  private BftMessageAssertions() {}

  /**
   * Asserts that a message received over the wire matches the expected one.
   *
   * <p>SECP256K1 signatures are deterministic, so the messages are compared in full, signatures
   * included. Other algorithms sign with fresh randomness, so every field but the signatures and
   * keys is compared instead. That still proves the actual message is genuine: decoding it verified
   * its signature and derived its sender from the verified key, and the sender is compared.
   *
   * @param expected the message the test expected
   * @param actual the message decoded from what the node sent
   */
  public static void assertMessageMatches(
      final BftMessage<?> expected, final BftMessage<?> actual) {
    if (DSAProviderFactory.getActiveDSA() instanceof SignatureAlgorithm) {
      assertThat(expected).isEqualToComparingFieldByFieldRecursively(actual);
      return;
    }
    // Value types are compared by their own equals: their fields include caches and buffer
    // offsets that differ between a message built in memory and one decoded from the wire.
    assertThat(actual)
        .usingRecursiveComparison()
        .ignoringFieldsMatchingRegexes(SIGNATURE_FIELDS)
        .withEqualsForType(Objects::equals, Bytes.class)
        .withEqualsForType(Objects::equals, Hash.class)
        .withEqualsForType(Objects::equals, Address.class)
        .withEqualsForType(Objects::equals, BlockHeader.class)
        .withEqualsForType(Objects::equals, Block.class)
        .isEqualTo(expected);
  }
}
