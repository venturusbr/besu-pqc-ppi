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
package org.hyperledger.besu.crypto.algorithms;

import static com.google.common.base.Preconditions.checkArgument;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SecureRandomProvider;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.types.FalconPrivateKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.FalconSignature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Falcon using BouncyCastle's low-level API, mirroring {@link MLDSA}: one class, with the parameter
 * set chosen at construction. BouncyCastle implements the Falcon round-3 encoding.
 *
 * <p>Falcon does not support public key recovery, so a transaction signed with it must carry the
 * signer's public key, exactly as for ML-DSA. Two things differ from {@link MLDSA}:
 *
 * <ul>
 *   <li>Signatures are variable-length, so a Falcon {@link DSAParametersSet} declares none.
 *   <li>A fresh {@link FalconSigner} is created for every operation. Signers hold per-operation
 *       state and are not thread-safe, and verification runs concurrently in the transaction pool.
 * </ul>
 *
 * <p>Supporting another parameter set means adding its {@link DSAParametersSet} entry and a row to
 * {@link #PARAMETERS}, with sizes measured from BouncyCastle.
 */
public class Falcon implements DigitalSignatureAlgorithm {
  private static final Logger LOG = LoggerFactory.getLogger(Falcon.class);

  /**
   * What a Falcon parameter set needs beyond {@link DSAParametersSet}: the BouncyCastle parameters,
   * the lengths of the private key components {@code f}, {@code g} and {@code F}, and the largest
   * signature accepted as structurally valid.
   *
   * @param bouncyCastle the BouncyCastle parameter set
   * @param fLength length of {@code f} in bytes
   * @param gLength length of {@code g} in bytes
   * @param capitalFLength length of {@code F} in bytes
   * @param maxSignatureLength largest signature accepted by {@link FalconSignature#isValid}
   */
  public record Parameters(
      FalconParameters bouncyCastle,
      int fLength,
      int gLength,
      int capitalFLength,
      int maxSignatureLength) {}

  /**
   * Falcon-512.
   *
   * <p>The maximum signature length, 752, is the Falcon-512 maximum used by liboqs. It was chosen
   * over the smaller bound BouncyCastle applies internally ({@code CRYPTO_BYTES = 690} in {@code
   * FalconNIST}), because BouncyCastle uses 690 only to size its own signing buffer and does not
   * enforce it when verifying: its verifier checks the header byte and then decodes, whatever the
   * length. A transaction may be signed by a client using another implementation, so capping at 690
   * could reject a signature that would still verify. 752 never rejects a signature either library
   * considers well-sized. The cap exists to reject oversized input before any decoding work, not to
   * decide validity: anything longer cannot verify anyway, since BouncyCastle's decoder rejects
   * even a single trailing byte. Signatures observed from BouncyCastle range from 648 to 662 bytes.
   *
   * <p>This is also why signatures are not padded to a fixed length: BouncyCastle rejects Falcon's
   * zero-padded format, so they are carried at their natural, variable length.
   */
  private static final Parameters FALCON_512 =
      new Parameters(FalconParameters.falcon_512, 384, 384, 512, 752);

  private static final Map<DSAParametersSet, Parameters> PARAMETERS =
      Map.of(DSAParametersSet.FALCON512, FALCON_512);

  private final DSAParametersSet parametersSet;
  private final Parameters parameters;

  /**
   * Instantiates Falcon for one parameter set.
   *
   * @param parametersSet a Falcon parameter set
   * @throws IllegalArgumentException if {@code parametersSet} is not a supported Falcon parameter
   *     set
   */
  public Falcon(final DSAParametersSet parametersSet) {
    this.parametersSet = parametersSet;
    this.parameters = parametersFor(parametersSet);
  }

  /**
   * Looks up the Falcon-specific parameters of a parameter set.
   *
   * @param parametersSet a Falcon parameter set
   * @return its parameters
   * @throws IllegalArgumentException if {@code parametersSet} is not a supported Falcon parameter
   *     set
   */
  public static Parameters parametersFor(final DSAParametersSet parametersSet) {
    final Parameters found = PARAMETERS.get(parametersSet);
    checkArgument(found != null, "Not a supported Falcon parameter set: %s", parametersSet);
    return found;
  }

  /**
   * The parameter sets this class supports.
   *
   * @return the supported Falcon parameter sets
   */
  public static Set<DSAParametersSet> supportedParameterSets() {
    return PARAMETERS.keySet();
  }

  @Override
  public Signature sign(final Bytes data, final PrivateKey sk) {
    checkArgument(
        sk instanceof FalconPrivateKey falconSk && falconSk.getParametersSet() == parametersSet,
        "Expected a %s private key, got %s",
        parametersSet.getName(),
        sk == null ? null : sk.getAlgorithm());

    final FalconSigner signer = new FalconSigner();
    signer.init(
        true,
        new ParametersWithRandom(
            ((FalconPrivateKey) sk).toBouncyCastle(), SecureRandomProvider.createSecureRandom()));
    return FalconSignature.create(
        Bytes.wrap(signer.generateSignature(data.toArrayUnsafe())), parametersSet);
  }

  /**
   * Verifies a signature. Malformed input -- a key of the wrong length, or bytes that do not decode
   * as a Falcon signature -- is reported as a failed verification rather than an exception, because
   * both reach here from untrusted transactions.
   */
  @Override
  public Boolean verify(final Bytes data, final Signature signature, final PublicKey pk) {
    final byte[] pkBytes = pk.getEncoded();
    if (pkBytes == null || pkBytes.length != parametersSet.getPublicKeyLength()) {
      return false;
    }
    final Bytes signatureBytes = signature.encodedBytes();
    if (signatureBytes == null || signatureBytes.isEmpty()) {
      return false;
    }

    try {
      final FalconSigner verifier = new FalconSigner();
      verifier.init(false, new FalconPublicKeyParameters(parameters.bouncyCastle(), pkBytes));
      return verifier.verifySignature(data.toArrayUnsafe(), signatureBytes.toArrayUnsafe());
    } catch (final RuntimeException e) {
      LOG.debug("{} signature could not be decoded: {}", parametersSet.getName(), e.getMessage());
      return false;
    }
  }

  @Override
  public KeyPair generateNodeKeyPair() {
    final FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
    generator.init(
        new FalconKeyGenerationParameters(
            SecureRandomProvider.createSecureRandom(), parameters.bouncyCastle()));
    final AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

    final FalconPrivateKey sk =
        FalconPrivateKey.fromBouncyCastle(
            (FalconPrivateKeyParameters) keyPair.getPrivate(), parametersSet);
    final Bytes rawPk = Bytes.wrap(((FalconPublicKeyParameters) keyPair.getPublic()).getH());

    return KeyFactory.createKeyPair(Bytes.wrap(sk.getEncoded()), rawPk, parametersSet);
  }

  @Override
  public DSAParametersSet getDsaParametersSet() {
    return parametersSet;
  }
}
