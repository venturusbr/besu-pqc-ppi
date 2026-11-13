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
package org.hyperledger.besu.crypto.algorithms;

import static com.google.common.base.Preconditions.checkArgument;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SecureRandomProvider;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MLDSA implements DigitalSignatureAlgorithm {
  private static final Map<String, MLDSAParameters> RENAMING_TO_LIB = new HashMap<>();
  private final DSAParametersSet mldsaParameters;
  private final MLDSAParameters selectedBCParameter;
  private static final Logger LOG = LoggerFactory.getLogger(MLDSA.class);

  static {
    RENAMING_TO_LIB.put(DSAParametersSet.MLDSA44.getName(), MLDSAParameters.ml_dsa_44);
    RENAMING_TO_LIB.put(DSAParametersSet.MLDSA65.getName(), MLDSAParameters.ml_dsa_65);
    RENAMING_TO_LIB.put(DSAParametersSet.MLDSA87.getName(), MLDSAParameters.ml_dsa_87);
  }

  public MLDSA(final DSAParametersSet mldsaParameters) {
    Security.addProvider(new BouncyCastlePQCProvider());
    this.mldsaParameters = mldsaParameters;
    this.selectedBCParameter = RENAMING_TO_LIB.get(mldsaParameters.getName());
  }

  /**
   * Signs the data. A failure inside BouncyCastle's signer is rethrown as an {@link
   * IllegalStateException} that carries it as the cause: logging it and going on left the signature
   * null, so the caller failed with a NullPointerException that hid the real error.
   *
   * <p>The key is checked up front, as {@link Falcon#sign} does, so a key of another type or
   * parameter set, or of the wrong length, is refused with a clear message instead of failing
   * inside BouncyCastle's key constructor.
   *
   * @throws IllegalArgumentException if {@code sk} is not an ML-DSA private key of this parameter
   *     set and length
   * @throws IllegalStateException if BouncyCastle cannot produce the signature
   */
  @Override
  public Signature sign(final Bytes data, final PrivateKey sk) {
    final byte[] skBytes = sk == null ? null : sk.getEncoded();
    checkArgument(
        sk instanceof MLDSAPrivateKey
            && mldsaParameters.getName().equals(sk.getAlgorithm())
            && skBytes != null
            && skBytes.length == mldsaParameters.getPrivateKeyLength(),
        "Expected a %s private key of %s bytes, got %s",
        mldsaParameters.getName(),
        mldsaParameters.getPrivateKeyLength(),
        sk == null
            ? null
            : sk.getAlgorithm() + " key of " + (skBytes == null ? 0 : skBytes.length) + " bytes");

    MLDSAPrivateKeyParameters skParams =
        new MLDSAPrivateKeyParameters(selectedBCParameter, skBytes);
    // A signer per call: MLDSASigner accumulates the message in an internal SHAKE state
    // between init and generateSignature, so one instance shared by the node's threads
    // corrupts that state when two of them sign or verify at once.
    final MLDSASigner signer = new MLDSASigner();
    signer.init(true, skParams);
    signer.update(data.toArrayUnsafe(), 0, data.size());

    final byte[] signature;
    try {
      signature = signer.generateSignature();
    } catch (DataLengthException | CryptoException e) {
      throw new IllegalStateException(mldsaParameters.getName() + " signing failed", e);
    }
    return SignatureFactory.createSignatureFromBytes(Bytes.wrap(signature), mldsaParameters);
  }

  /**
   * Verifies a signature. A key of the wrong length is reported as a failed verification rather
   * than an exception, as {@link Falcon#verify} does: BouncyCastle unpacks the key at fixed offsets
   * and throws on any other length, and the key reaches here from untrusted transactions.
   */
  @Override
  public Boolean verify(final Bytes data, final Signature signature, final PublicKey pk) {
    final byte[] pkBytes = pk.getEncoded();
    if (pkBytes == null || pkBytes.length != mldsaParameters.getPublicKeyLength()) {
      return false;
    }
    MLDSAPublicKeyParameters pkParams = new MLDSAPublicKeyParameters(selectedBCParameter, pkBytes);
    // See sign: the signer is stateful, so it is never shared between calls.
    final MLDSASigner verifier = new MLDSASigner();
    verifier.init(false, pkParams);
    verifier.update(data.toArrayUnsafe(), 0, data.size());

    try {
      return verifier.verifySignature(signature.encodedBytes().toArrayUnsafe());
    } catch (final RuntimeException e) {
      LOG.debug(
          "{} signature could not be verified: {}", mldsaParameters.getName(), e.getMessage());
      return false;
    }
  }

  @Override
  public KeyPair generateNodeKeyPair() {
    MLDSAKeyPairGenerator mldsaKpGenerator = new MLDSAKeyPairGenerator();
    KeyGenerationParameters genParams =
        new MLDSAKeyGenerationParameters(
            SecureRandomProvider.createSecureRandom(), selectedBCParameter);

    mldsaKpGenerator.init(genParams);
    AsymmetricCipherKeyPair mldsaKp = mldsaKpGenerator.generateKeyPair();

    MLDSAPrivateKeyParameters skParams = (MLDSAPrivateKeyParameters) mldsaKp.getPrivate();
    MLDSAPublicKeyParameters pkParams = (MLDSAPublicKeyParameters) mldsaKp.getPublic();

    Bytes rawSk = Bytes.wrap(skParams.getEncoded());
    Bytes rawPk = Bytes.wrap(pkParams.getEncoded());

    KeyPair kp = KeyFactory.createKeyPair(rawSk, rawPk, mldsaParameters);

    return kp;
  }

  @Override
  public DSAParametersSet getDsaParametersSet() {
    return mldsaParameters;
  }

  public static MLDSAParameters getBCMLDSAParametersByDSAParameterName(
      final String DSAParameterName) {
    return RENAMING_TO_LIB.get(DSAParameterName);
  }
}
