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
package org.hyperledger.besu.consensus.clique;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.ParsedExtraData;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyDecoder;
import org.hyperledger.besu.ethereum.core.encoding.PublicKeyEncoder;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import com.google.common.base.Suppliers;
import com.google.common.collect.Lists;
import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the data structure stored in the extraData field of the BlockHeader used when
 * operating under an Clique consensus mechanism.
 *
 * <p>The layout depends on whether the active algorithm can recover a public key from a signature.
 * When it can (SECP256K1), the layout is Clique's original one and the proposer is recovered from
 * the seal:
 *
 * <pre>
 *   vanity(32) | validators(20 * n) | seal(65)
 * </pre>
 *
 * <p>When it cannot (ML-DSA, Falcon and their hybrids), the seal alone does not identify its
 * proposer, so the header also carries the proposer's public key -- only the half that cannot be
 * recovered, for a hybrid -- and the seal is verified against it. Seals of these algorithms are
 * larger and, for Falcon, of variable length, so both fields are sized by a fixed footer:
 *
 * <pre>
 *   vanity(32) | validators(20 * n) | key(K) | seal(S) | K(2) | S(2)
 * </pre>
 *
 * <p>An unsealed header has K = S = 0. The genesis block of such a network may instead use the
 * original layout with an all-zero seal, so existing genesis files and tooling keep working; the
 * two cannot be confused, as their lengths differ modulo the size of an address.
 */
public class CliqueExtraData implements ParsedExtraData {
  private static final Logger LOG = LoggerFactory.getLogger(CliqueExtraData.class);

  /** The constant EXTRA_VANITY_LENGTH. */
  public static final int EXTRA_VANITY_LENGTH = 32;

  /** Size of each of the two lengths in the footer of the layout that carries the key. */
  private static final int FOOTER_FIELD_LENGTH = 2;

  private static final int FOOTER_LENGTH = 2 * FOOTER_FIELD_LENGTH;
  private static final int MAX_FOOTER_FIELD_VALUE = 0xFFFF;

  private final Bytes vanityData;
  private final List<Address> validators;
  private final Optional<Signature> proposerSeal;
  private final Optional<PublicKey> proposerPublicKey;
  private final Supplier<Address> proposerAddress;

  /**
   * Instantiates a new Clique extra data that carries no public key, which is only sufficient for
   * algorithms that support public key recovery.
   *
   * @param vanityData the vanity data
   * @param proposerSeal the proposer seal
   * @param validators the validators
   * @param header the header
   */
  public CliqueExtraData(
      final Bytes vanityData,
      final Signature proposerSeal,
      final List<Address> validators,
      final BlockHeader header) {
    this(vanityData, proposerSeal, validators, Optional.empty(), header);
  }

  /**
   * Instantiates a new Clique extra data.
   *
   * @param vanityData the vanity data
   * @param proposerSeal the proposer seal
   * @param validators the validators
   * @param proposerPublicKey the part of the proposer's public key the header carries, required to
   *     seal or verify under an algorithm without public key recovery; see {@link
   *     #proposerKeyToCarry}
   * @param header the header
   */
  public CliqueExtraData(
      final Bytes vanityData,
      final Signature proposerSeal,
      final List<Address> validators,
      final Optional<PublicKey> proposerPublicKey,
      final BlockHeader header) {

    checkNotNull(vanityData);
    checkNotNull(validators);
    checkNotNull(proposerPublicKey);
    checkNotNull(header);
    checkArgument(vanityData.size() == EXTRA_VANITY_LENGTH);

    this.vanityData = vanityData;
    this.proposerSeal = Optional.ofNullable(proposerSeal);
    this.validators = validators;
    this.proposerPublicKey = proposerPublicKey;
    proposerAddress =
        Suppliers.memoize(() -> CliqueBlockHashing.recoverProposerAddress(header, this));
  }

  /**
   * Create without proposer seal.
   *
   * @param vanityData the vanity data
   * @param validators the validators
   * @return the bytes
   */
  public static Bytes createWithoutProposerSeal(
      final Bytes vanityData, final List<Address> validators) {
    return CliqueExtraData.encodeUnsealed(vanityData, validators);
  }

  /**
   * Decode header to get clique extra data.
   *
   * @param header the header
   * @return the clique extra data
   */
  public static CliqueExtraData decode(final BlockHeader header) {
    final Object inputExtraData = header.getParsedExtraData();
    if (inputExtraData instanceof CliqueExtraData) {
      return (CliqueExtraData) inputExtraData;
    }
    LOG.warn(
        "Expected a CliqueExtraData instance but got {}. Reparsing required.",
        inputExtraData != null ? inputExtraData.getClass().getName() : "null");
    return decodeRaw(header);
  }

  /**
   * Decode raw to get clique extra data.
   *
   * @param header the header
   * @return the clique extra data
   */
  static CliqueExtraData decodeRaw(final BlockHeader header) {
    final Bytes input = header.getExtraData();
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();
    if (!carriesProposerKey(dsa) || isUnsealedGenesisInRecoverableLayout(header, input)) {
      return decodeRecoverableLayout(header, input);
    }
    return decodeKeyCarryingLayout(header, input, dsa);
  }

  private static CliqueExtraData decodeRecoverableLayout(
      final BlockHeader header, final Bytes input) {
    if (input.size() < EXTRA_VANITY_LENGTH + SECPSignature.BYTES_REQUIRED) {
      throw new IllegalArgumentException(
          "Invalid Bytes supplied - too short to produce a valid Clique Extra Data object.");
    }

    final int validatorByteCount =
        input.size() - EXTRA_VANITY_LENGTH - SECPSignature.BYTES_REQUIRED;
    if ((validatorByteCount % Address.SIZE) != 0) {
      throw new IllegalArgumentException("Bytes is of invalid size - i.e. contains unused bytes.");
    }

    final Bytes vanityData = input.slice(0, EXTRA_VANITY_LENGTH);
    final List<Address> validators =
        extractValidators(input.slice(EXTRA_VANITY_LENGTH, validatorByteCount));

    final int proposerSealStartIndex = input.size() - SECPSignature.BYTES_REQUIRED;
    final Signature proposerSeal = parseProposerSeal(input.slice(proposerSealStartIndex));

    return new CliqueExtraData(vanityData, proposerSeal, validators, header);
  }

  private static CliqueExtraData decodeKeyCarryingLayout(
      final BlockHeader header, final Bytes input, final DigitalSignatureAlgorithm dsa) {
    if (input.size() < EXTRA_VANITY_LENGTH + FOOTER_LENGTH) {
      throw new IllegalArgumentException(
          "Invalid Bytes supplied - too short to produce a valid Clique Extra Data object.");
    }

    final int footerStart = input.size() - FOOTER_LENGTH;
    final int keyLength = input.slice(footerStart, FOOTER_FIELD_LENGTH).toInt();
    final int sealLength =
        input.slice(footerStart + FOOTER_FIELD_LENGTH, FOOTER_FIELD_LENGTH).toInt();

    final int validatorByteCount = footerStart - EXTRA_VANITY_LENGTH - keyLength - sealLength;
    if (validatorByteCount < 0) {
      throw new IllegalArgumentException(
          "Invalid Bytes supplied - too short for the key and seal lengths it states.");
    }
    if ((validatorByteCount % Address.SIZE) != 0) {
      throw new IllegalArgumentException("Bytes is of invalid size - i.e. contains unused bytes.");
    }
    if (sealLength > 0 && keyLength == 0) {
      throw new IllegalArgumentException(
          dsa.getDsaParametersSet().getName()
              + " cannot recover the proposer's public key, but the sealed header carries none.");
    }

    // PublicKeyDecoder checks the length of a hybrid's carried half, but not of a whole key.
    if (keyLength > 0
        && !(dsa instanceof HybridDigitalSignatureAlgorithm)
        && keyLength != dsa.getDsaParametersSet().getPublicKeyLength()) {
      throw new IllegalArgumentException(
          "Expected a "
              + dsa.getDsaParametersSet().getName()
              + " public key of "
              + dsa.getDsaParametersSet().getPublicKeyLength()
              + " bytes, got "
              + keyLength);
    }

    final Bytes vanityData = input.slice(0, EXTRA_VANITY_LENGTH);
    final int keyStart = EXTRA_VANITY_LENGTH + validatorByteCount;
    final List<Address> validators =
        extractValidators(input.slice(EXTRA_VANITY_LENGTH, validatorByteCount));

    final Optional<PublicKey> proposerPublicKey;
    final Signature proposerSeal;
    try {
      proposerPublicKey =
          keyLength == 0
              ? Optional.empty()
              : PublicKeyDecoder.fromProvidedBytes(dsa, input.slice(keyStart, keyLength));
      proposerSeal =
          sealLength == 0
              ? null
              : SignatureFactory.createSignatureFromBytes(
                  input.slice(keyStart + keyLength, sealLength), dsa.getDsaParametersSet());
    } catch (final IllegalArgumentException e) {
      throw e;
    } catch (final RuntimeException e) {
      // Header bytes are untrusted input; report a malformed key or seal as invalid data.
      throw new IllegalArgumentException(
          "Invalid proposer public key or seal in Clique extra data: " + e.getMessage(), e);
    }

    return new CliqueExtraData(vanityData, proposerSeal, validators, proposerPublicKey, header);
  }

  /*
   * The original layout's genesis form -- an all-zero seal -- is still accepted for the genesis
   * block of a network whose algorithm cannot recover keys, so genesis files built for it need no
   * change. Its length never matches the key-carrying layout's: the parts other than the
   * validators total 97 bytes in one and 36 in the other, which differ modulo 20.
   */
  private static boolean isUnsealedGenesisInRecoverableLayout(
      final BlockHeader header, final Bytes input) {
    final int fixedLength = EXTRA_VANITY_LENGTH + SECPSignature.BYTES_REQUIRED;
    return header.getNumber() == BlockHeader.GENESIS_BLOCK_NUMBER
        && input.size() >= fixedLength
        && (input.size() - fixedLength) % Address.SIZE == 0
        && input.slice(input.size() - SECPSignature.BYTES_REQUIRED).isZero();
  }

  /**
   * Whether headers sealed with this algorithm carry the proposer's public key, which is the case
   * whenever the key cannot be recovered from the seal.
   *
   * @param dsa the algorithm the network seals blocks with
   * @return true if the header carries the proposer's public key
   */
  static boolean carriesProposerKey(final DigitalSignatureAlgorithm dsa) {
    return !(dsa instanceof PublicKeyRecoverable);
  }

  /**
   * The part of a proposer's public key that a header sealed under the active algorithm carries:
   * nothing for an algorithm with public key recovery, the non-recoverable half of a hybrid key,
   * and the whole key otherwise. These are the same rules transactions and consensus messages
   * follow.
   *
   * @param nodePublicKey the proposer's full public key
   * @return the key to carry, if any
   */
  public static Optional<PublicKey> proposerKeyToCarry(final PublicKey nodePublicKey) {
    final DigitalSignatureAlgorithm dsa = DSAProviderFactory.getActiveDSA();
    if (!carriesProposerKey(dsa)) {
      return Optional.empty();
    }
    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    PublicKeyEncoder.encodeByDsa(nodePublicKey, dsa, out);
    return PublicKeyDecoder.fromProvidedBytes(dsa, RLP.input(out.encoded()).readBytes());
  }

  /**
   * Gets proposer address.
   *
   * @return the proposer address
   */
  public synchronized Address getProposerAddress() {
    return proposerAddress.get();
  }

  private static Signature parseProposerSeal(final Bytes proposerSealRaw) {
    if (proposerSealRaw.isZero()) {
      return null;
    }
    return SignatureFactory.createSignatureFromBytes(
        proposerSealRaw, DSAProviderFactory.getActiveDsaParametersSet());
  }

  private static List<Address> extractValidators(final Bytes validatorsRaw) {
    final List<Address> result = Lists.newArrayList();
    final int countValidators = validatorsRaw.size() / Address.SIZE;
    for (int i = 0; i < countValidators; i++) {
      final int startIndex = i * Address.SIZE;
      result.add(Address.wrap(validatorsRaw.slice(startIndex, Address.SIZE)));
    }
    return result;
  }

  /**
   * Encode to bytes.
   *
   * @return the bytes
   */
  public Bytes encode() {
    return encode(vanityData, validators, proposerPublicKey, proposerSeal);
  }

  /**
   * Encode unsealed to bytes.
   *
   * @param vanityData the vanity data
   * @param validators the validators
   * @return the bytes
   */
  public static Bytes encodeUnsealed(final Bytes vanityData, final List<Address> validators) {
    return encode(vanityData, validators, Optional.empty(), Optional.empty());
  }

  /**
   * The part of the extra data the proposer seal signs: everything but the seal itself. For the
   * key-carrying layout this includes the key, so it cannot be swapped once the header is sealed.
   *
   * @return the bytes covered by the proposer seal
   */
  Bytes encodeWithoutProposerSeal() {
    final Bytes vanityAndValidators = Bytes.concatenate(vanityData, encodeValidators(validators));
    if (!carriesProposerKey(DSAProviderFactory.getActiveDSA())) {
      return vanityAndValidators;
    }
    final Bytes key = encodeKey(proposerPublicKey);
    return Bytes.concatenate(vanityAndValidators, key, footerField(key.size()));
  }

  private static Bytes encode(
      final Bytes vanityData,
      final List<Address> validators,
      final Optional<PublicKey> proposerPublicKey,
      final Optional<Signature> proposerSeal) {
    final Bytes validatorData = encodeValidators(validators);
    if (!carriesProposerKey(DSAProviderFactory.getActiveDSA())) {
      return Bytes.concatenate(
          vanityData,
          validatorData,
          proposerSeal
              .map(Signature::encodedBytes)
              .orElse(Bytes.wrap(new byte[SECPSignature.BYTES_REQUIRED])));
    }
    final Bytes key = encodeKey(proposerPublicKey);
    final Bytes seal = proposerSeal.map(Signature::encodedBytes).orElse(Bytes.EMPTY);
    return Bytes.concatenate(
        vanityData, validatorData, key, seal, footerField(key.size()), footerField(seal.size()));
  }

  private static Bytes encodeValidators(final List<Address> validators) {
    return Bytes.concatenate(validators.stream().map(Address::getBytes).toList());
  }

  private static Bytes encodeKey(final Optional<PublicKey> publicKey) {
    return publicKey.map(key -> Bytes.wrap(key.getEncoded())).orElse(Bytes.EMPTY);
  }

  private static Bytes footerField(final int length) {
    checkArgument(
        length <= MAX_FOOTER_FIELD_VALUE, "Field of %s bytes is too long to encode", length);
    return Bytes.ofUnsignedShort(length);
  }

  /**
   * Gets vanity data.
   *
   * @return the vanity data
   */
  public Bytes getVanityData() {
    return vanityData;
  }

  /**
   * Gets proposer seal.
   *
   * @return the proposer seal
   */
  public Optional<Signature> getProposerSeal() {
    return proposerSeal;
  }

  /**
   * Gets the part of the proposer's public key the header carries, present only for algorithms that
   * cannot recover it from the seal.
   *
   * @return the proposer public key
   */
  public Optional<PublicKey> getProposerPublicKey() {
    return proposerPublicKey;
  }

  /**
   * Gets validators.
   *
   * @return the validators
   */
  public List<Address> getValidators() {
    return validators;
  }

  /**
   * Create genesis extra data string.
   *
   * @param validators the validators
   * @return the string
   */
  public static String createGenesisExtraDataString(final List<Address> validators) {
    return CliqueExtraData.createWithoutProposerSeal(Bytes.wrap(new byte[32]), validators)
        .toString();
  }
}
