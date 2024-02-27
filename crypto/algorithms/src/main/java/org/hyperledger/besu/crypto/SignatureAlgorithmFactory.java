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
package org.hyperledger.besu.crypto;

import com.google.common.annotations.VisibleForTesting;

import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.AbstractCrystalsDilithium3;
import org.hyperledger.besu.crypto.pqc.falcon.Falcon;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** The Signature algorithm factory. */
public class SignatureAlgorithmFactory {

  private static final Logger LOG = LoggerFactory.getLogger(SignatureAlgorithmFactory.class);

  private static SignatureAlgorithm instance = null;
  private static final AbstractCrystalsDilithium3 pqcInstance = null;
  private static final SphincsPlus sphincsInstance = null;
  private static final Falcon falconInstance = null;
  private static final PqcSignatureAlgorithm genericPqcInstance = null;
  private static String pqcAlgorithmName = "none";

  private SignatureAlgorithmFactory() {}

  /** Sets default instance. */
  public static void setDefaultInstance() {
    instance = SignatureAlgorithmType.createDefault().getInstance();
  }

  /**
   * Sets instance.
   *
   * @param signatureAlgorithmType the signature algorithm type
   * @throws IllegalStateException the illegal state exception
   */
  public static void setInstance(final SignatureAlgorithmType signatureAlgorithmType)
      throws IllegalStateException {
    if (instance != null) {
      throw new IllegalStateException(
          "Instance of SignatureAlgorithmFactory can only be set once.");
    }

    instance = signatureAlgorithmType.getInstance();

    if (!SignatureAlgorithmType.isDefault(instance)) {
      LOG.info(
          "The signature algorithm uses the elliptic curve {}. The usage of alternative elliptic curves is still experimental.",
          instance.getCurveName());
    }
  }

  /**
   * Sets a custom SignatureAlgorithm instance directly.
   *
   * @param signatureAlgorithm the custom signature algorithm instance
   * @throws IllegalStateException if instance is already set
   */
  public static void setInstance(final SignatureAlgorithm signatureAlgorithm)
      throws IllegalStateException {
    if (instance != null) {
      throw new IllegalStateException(
          "Instance of SignatureAlgorithmFactory can only be set once.");
    }

    instance = signatureAlgorithm;

    if (!SignatureAlgorithmType.isDefault(instance)) {
      LOG.info(
          "The signature algorithm uses the elliptic curve {}. The usage of alternative elliptic curves is still experimental.",
          instance.getCurveName());
    }
  }

  /**
   * getInstance will always return a valid SignatureAlgorithm and never null. This is necessary in
   * the unit tests be able to use the factory without having to call setInstance first.
   *
   * @return SignatureAlgorithm instance
   */
  public static SignatureAlgorithm getInstance() {
    return instance != null
        ? instance
        : SignatureAlgorithmType.DEFAULT_SIGNATURE_ALGORITHM_TYPE.get();
  }

  /**
   * getInstance will always return a valid SignatureAlgorithm and never null. This is necessary in
   * the unit tests be able to use the factory without having to call setInstance first.
   * @return PqcSignatureAlgorithm instance
  */
  public static PqcSignatureAlgorithm getPqcGenericInstance() {
    return genericPqcInstance != null
        ? genericPqcInstance
        : SignatureAlgorithmType.getGenericInstanceByName(pqcAlgorithmName);
  }

  public static AbstractCrystalsDilithium3 getPQCInstance() {
    return pqcInstance != null
        ? pqcInstance
        : SignatureAlgorithmType.DEFAULT_PQC_SIGNATURE_ALGORITHM_TYPE.get();
  }

  public static SphincsPlus getSphincsPlusInstance() {
    return sphincsInstance != null
        ? sphincsInstance
        : SignatureAlgorithmType.SPHINCS_PQC_SIGNATURE_ALGORITHM_TYPE.get();
  }

  public static Falcon getFalconInstance() {
    return falconInstance != null
        ? falconInstance
        : SignatureAlgorithmType.FALCON_PQC_SIGNATURE_ALGORITHM_TYPE.get();
  }

  /**
   * Is instance set boolean.
   *
   * @return the boolean
   */
  public static boolean isInstanceSet() {
    return instance != null;
  }

  /** Reset instance. */
  @VisibleForTesting
  public static void resetInstance() {
    instance = null;
  }

  public static void setpqcAlgorithmName(final String name) {
    pqcAlgorithmName = name;
  }

  public static String getPqcAlgorithmName() {
    return pqcAlgorithmName;
  }
}
