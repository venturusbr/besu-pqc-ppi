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
import org.hyperledger.besu.crypto.key.types.Falcon512PrivateKey;
import org.hyperledger.besu.crypto.key.types.Falcon512PublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.Falcon512Signature;

import java.security.PrivateKey;
import java.security.PublicKey;

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
 * Falcon-512 (FN-DSA) using BouncyCastle's low-level API, mirroring {@link MLDSA}.
 *
 * <p>Falcon does not support public key recovery, so a transaction signed with it must carry the
 * signer's public key, exactly as for ML-DSA. Two things differ from {@link MLDSA}:
 *
 * <ul>
 *   <li>Signatures are variable-length, so {@link DSAParametersSet#FALCON512} declares none.
 *   <li>A fresh {@link FalconSigner} is created for every operation. Signers hold per-operation
 *       state and are not thread-safe, and verification runs concurrently in the transaction pool.
 * </ul>
 */
public class Falcon512 implements DigitalSignatureAlgorithm {
  private static final Logger LOG = LoggerFactory.getLogger(Falcon512.class);

  private static final DSAParametersSet PARAMETERS = DSAParametersSet.FALCON512;
  private static final FalconParameters BC_PARAMETERS = FalconParameters.falcon_512;

  /** Default constructor. */
  public Falcon512() {}

  @Override
  public Signature sign(final Bytes data, final PrivateKey sk) {
    checkArgument(
        sk instanceof Falcon512PrivateKey,
        "Expected a Falcon-512 private key, got %s",
        sk == null ? null : sk.getClass().getName());

    final FalconSigner signer = new FalconSigner();
    signer.init(
        true,
        new ParametersWithRandom(
            ((Falcon512PrivateKey) sk).toBouncyCastle(BC_PARAMETERS),
            SecureRandomProvider.createSecureRandom()));
    return Falcon512Signature.create(Bytes.wrap(signer.generateSignature(data.toArrayUnsafe())));
  }

  /**
   * Verifies a signature. Malformed input -- a key of the wrong length, or bytes that do not decode
   * as a Falcon signature -- is reported as a failed verification rather than an exception, because
   * both reach here from untrusted transactions.
   */
  @Override
  public Boolean verify(final Bytes data, final Signature signature, final PublicKey pk) {
    final byte[] pkBytes = pk.getEncoded();
    if (pkBytes == null || pkBytes.length != Falcon512PublicKey.LENGTH) {
      return false;
    }
    final Bytes signatureBytes = signature.encodedBytes();
    if (signatureBytes == null || signatureBytes.isEmpty()) {
      return false;
    }

    try {
      final FalconSigner verifier = new FalconSigner();
      verifier.init(false, new FalconPublicKeyParameters(BC_PARAMETERS, pkBytes));
      return verifier.verifySignature(data.toArrayUnsafe(), signatureBytes.toArrayUnsafe());
    } catch (final RuntimeException e) {
      LOG.debug("Falcon-512 signature could not be decoded: {}", e.getMessage());
      return false;
    }
  }

  @Override
  public KeyPair generateNodeKeyPair() {
    final FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
    generator.init(
        new FalconKeyGenerationParameters(
            SecureRandomProvider.createSecureRandom(), BC_PARAMETERS));
    final AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

    final Falcon512PrivateKey sk =
        Falcon512PrivateKey.fromBouncyCastle((FalconPrivateKeyParameters) keyPair.getPrivate());
    final Bytes rawPk = Bytes.wrap(((FalconPublicKeyParameters) keyPair.getPublic()).getH());

    return KeyFactory.createKeyPair(Bytes.wrap(sk.getEncoded()), rawPk, PARAMETERS);
  }

  @Override
  public DSAParametersSet getDsaParametersSet() {
    return PARAMETERS;
  }
}
