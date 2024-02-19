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

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.io.Resources;
import org.apache.tuweni.bytes.Bytes32;

import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.DilithiumSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PrivateKey;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PublicKey;
import org.hyperledger.besu.crypto.pqc.falcon.Falcon;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconKeyPair;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPrivateKey;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPublicKey;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlus;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusPublicKey;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusKeyPair;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** The Key pair util. */
public class KeyPairUtil {
  private static final Logger LOG = LoggerFactory.getLogger(KeyPairUtil.class);
  private static final Supplier<SignatureAlgorithm> SIGNATURE_ALGORITHM =
      Suppliers.memoize(SignatureAlgorithmFactory::getInstance);
  
  private static final Supplier<DilithiumSignatureAlgorithm> PQC_SIGNATURE_ALGORITHM = 
      Suppliers.memoize(SignatureAlgorithmFactory::getPQCInstance);

  private static final Supplier<SphincsPlus> SPHINCS_SIGNATURE_ALGORITHM = 
      Suppliers.memoize(SignatureAlgorithmFactory::getSphincsPlusInstance);

  private static final Supplier<Falcon> FALCON_SIGNATURE_ALGORITHM = 
      Suppliers.memoize(SignatureAlgorithmFactory::getFalconInstance);

  /** Default constructor */
  private KeyPairUtil() {}

  /**
   * Load resource file string.
   *
   * @param resourcePath the resource path
   * @return the string
   */
  public static String loadResourceFile(final String resourcePath) {
    try {
      URL path = KeyPairUtil.class.getClassLoader().getResource(resourcePath);
      return Resources.toString(path, StandardCharsets.UTF_8).trim();
    } catch (Exception e) {
      throw new RuntimeException("Unable to load resource: " + resourcePath, e);
    }
  }

  /**
   * Load key pair from resource.
   *
   * @param resourcePath the resource path
   * @return the key pair
   */
  public static KeyPair loadKeyPairFromResource(final String resourcePath) {
    final KeyPair keyPair;
    String keyData = loadResourceFile(resourcePath);
    if (keyData == null || keyData.isEmpty()) {
      throw new IllegalArgumentException("Unable to load resource: " + resourcePath);
    }
    SECPPrivateKey privateKey =
        SIGNATURE_ALGORITHM.get().createPrivateKey(Bytes32.fromHexString((keyData)));
    keyPair = SIGNATURE_ALGORITHM.get().createKeyPair(privateKey);

    LOG.info("Loaded keyPair {} from {}", keyPair.getPublicKey().toString(), resourcePath);
    return keyPair;
  }

  /**
   * Load key pair.
   *
   * @param keyFile the key file
   * @return the key pair
   */
  public static KeyPair loadKeyPair(final File keyFile) {

    final KeyPair key;
    LOG.info("SECP privateKey path: " + keyFile);
    if (keyFile.exists()) {

      LOG.info("Attempting to load public key from {}", keyFile.getAbsolutePath());
      key = load(keyFile);
      LOG.info(
          "Loaded public key {} from {}", key.getPublicKey().toString(), keyFile.getAbsolutePath());
    } else {
      final SignatureAlgorithm signatureAlgorithm = SIGNATURE_ALGORITHM.get();
      key = signatureAlgorithm.generateKeyPair();
      storeKeyFile(key, keyFile.getParentFile().toPath());

      LOG.info(
          "Generated new {} public key {} and stored it to {}",
          signatureAlgorithm.getCurveName(),
          key.getPublicKey().toString(),
          keyFile.getAbsolutePath());
    }
    return key;
  }

  public static Dilithium3KeyPair loadPqcKeyPair(final File privateKeyFile, final File publicKeyFile) {

    final Dilithium3KeyPair key;
    if (privateKeyFile.exists() && publicKeyFile.exists()) {

      key = loadPqc(privateKeyFile, publicKeyFile);
      LOG.info(
          "Loaded PQC private key {} from {}", key.getPrivateKey().getEncoded().length, privateKeyFile.getAbsolutePath());
      LOG.info(
          "Loaded PQC public key {} from {}", key.getPublicKey().getEncoded().length, publicKeyFile.getAbsolutePath());
    } else {
      final DilithiumSignatureAlgorithm signatureAlgorithm = PQC_SIGNATURE_ALGORITHM.get();
      key = signatureAlgorithm.generateKeyPair();
      storeKeyFile(key, privateKeyFile.getParentFile().toPath());

      LOG.info(
          "Generated new PQC public key {} and stored it to {}",
          key.getPublicKey().toString(),
          publicKeyFile.getAbsolutePath());
    }
    return key;
  }

  public static SphincsPlusKeyPair loadSphincsKeyPair(final File privateKeyFile, final File publicKeyFile) {

    final SphincsPlusKeyPair key;
    if (privateKeyFile.exists() && publicKeyFile.exists()) {

      key = loadSphincs(privateKeyFile, publicKeyFile);
      LOG.info(
          "Loaded Sphincs private key {} from {}", key.getPrivateKey().getEncoded().length, privateKeyFile.getAbsolutePath());
      LOG.info(
          "Loaded Sphincs public key {} from {}", key.getPublicKey().getEncoded().length, publicKeyFile.getAbsolutePath());
    } else {
      final SphincsPlus signatureAlgorithm = SPHINCS_SIGNATURE_ALGORITHM.get();
      key = signatureAlgorithm.generateKeyPair();
      storeKeyFile(key, privateKeyFile.getParentFile().toPath());

      LOG.info(
          "Generated new Sphincs public key {} and stored it to {}",
          key.getPublicKey().toString(),
          publicKeyFile.getAbsolutePath());
    }
    return key;
  }

  public static FalconKeyPair loadFalconKeyPair(final File privateKeyFile, final File publicKeyFile) {

    final FalconKeyPair key;
    if (privateKeyFile.exists() && publicKeyFile.exists()) {

      key = loadFalcon(privateKeyFile, publicKeyFile);
      LOG.info(
          "Loaded Falcon private key {} from {}", key.getPrivateKey().getEncoded().length, privateKeyFile.getAbsolutePath());
      LOG.info(
          "Loaded Falcon public key {} from {}", key.getPublicKey().getEncoded().length, publicKeyFile.getAbsolutePath());
    } else {
      final Falcon signatureAlgorithm = FALCON_SIGNATURE_ALGORITHM.get();
      key = signatureAlgorithm.generateKeyPair();
      storeKeyFile(key, privateKeyFile.getParentFile().toPath());

      LOG.info(
          "Generated new Falcon public key {} and stored it to {}",
          key.getPublicKey().toString(),
          publicKeyFile.getAbsolutePath());
    }
    return key;
  }

  /**
   * Load key pair.
   *
   * @param directory the directory
   * @return the key pair
   */
  public static KeyPair loadKeyPair(final Path directory) {
    return loadKeyPair(getDefaultKeyFile(directory));
  }

  public static Dilithium3KeyPair loadPQCKeyPair(final Path directory) {
    return loadPqcKeyPair(getDefaultPqcPrivateKeyFile(directory), getDefaultPqcPublicKeyFile(directory));
  }

  public static SphincsPlusKeyPair loadSphincsKeyPair(final Path directory) {
    return loadSphincsKeyPair(getDefaultSphincsPrivateKeyFile(directory), getDefaultSphincsPublicKeyFile(directory));
  }

  public static FalconKeyPair loadFalconKeyPair(final Path directory) {
    return loadFalconKeyPair(getDefaultFalconPrivateKeyFile(directory), getDefaultFalconPublicKeyFile(directory));
  }

  /**
   * Store key file.
   *
   * @param keyPair the key pair
   * @param homeDirectory the home directory
   */
  public static void storeKeyFile(final KeyPair keyPair, final Path homeDirectory) {
    try {
      storeKeyPair(keyPair, getDefaultKeyFile(homeDirectory));
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot store generated private key.");
    }
  }

  public static void storeKeyFile(final Dilithium3KeyPair keyPair, final Path homeDirectory) {
    try {
      storeKeyPair(keyPair, getDefaultKeyFile(homeDirectory));
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot store generated private key.");
    }
  }

  public static void storeKeyFile(final SphincsPlusKeyPair keyPair, final Path homeDirectory) {
    try {
      storeKeyPair(keyPair, getDefaultKeyFile(homeDirectory));
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot store generated private key.");
    }
  }

  public static void storeKeyFile(final FalconKeyPair keyPair, final Path homeDirectory) {
    try {
      storeKeyPair(keyPair, getDefaultKeyFile(homeDirectory));
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot store generated private key.");
    }
  }

  /**
   * Gets default key file.
   *
   * @param directory the directory
   * @return the default key file
   */
  public static File getDefaultKeyFile(final Path directory) {
    return directory.resolve("key").toFile();
  }

  public static File getDefaultPqcPrivateKeyFile(final Path directory) {
    return directory.resolve("pqc-key").toFile();
  }

  public static File getDefaultPqcPublicKeyFile(final Path directory) {
    return directory.resolve("pqc-key.pub").toFile();
  }

  public static File getDefaultSphincsPrivateKeyFile(final Path directory) {
    return directory.resolve("sphincs-key").toFile();
  }

  public static File getDefaultSphincsPublicKeyFile(final Path directory) {
    return directory.resolve("sphincs-key.pub").toFile();
  }

  public static File getDefaultFalconPrivateKeyFile(final Path directory) {
    return directory.resolve("falcon-key").toFile();
  }

  public static File getDefaultFalconPublicKeyFile(final Path directory) {
    return directory.resolve("falcon-key.pub").toFile();
  }

  /**
   * Load key pair.
   *
   * @param file the file
   * @return the key pair
   */
  public static KeyPair load(final File file) {
    return SIGNATURE_ALGORITHM.get().createKeyPair(loadPrivateKeyFromFile(file));
  }

  public static Dilithium3KeyPair loadPqc(final File privateKeyFile, final File publicKeyFile) {
    return PQC_SIGNATURE_ALGORITHM.get().createDilithium3KeyPair(loadPQCPrivateKeyFromFile(privateKeyFile),
        loadPQCPublicKeyFromFile(publicKeyFile));
  }

  public static SphincsPlusKeyPair loadSphincs(final File privateKeyFile, final File publicKeyFile) {
    return SPHINCS_SIGNATURE_ALGORITHM.get().createSphincsPlusKeyPair(loadSphincsPrivateKeyFromFile(privateKeyFile), 
    loadSphincsPublicKeyFromFile(publicKeyFile));
  }

  public static FalconKeyPair loadFalcon(final File privateKeyFile, final File publicKeyFile) {
    return FALCON_SIGNATURE_ALGORITHM.get().createFalconKeyPair(loadFalconPrivateKeyFromFile(privateKeyFile), 
    loadFalconPublicKeyFromFile(publicKeyFile));
  }

  private static String readHexKey(final File file) throws IOException {
    final List<String> info = Files.readAllLines(file.toPath());
    if (info.size() != 1) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
    return info.get(0);
  }

  /**
   * Load secp private key.
   *
   * @param file the file
   * @return the secp private key
   */
  static SECPPrivateKey loadPrivateKeyFromFile(final File file) {
    try {
      String hexKey = readHexKey(file);
      return SIGNATURE_ALGORITHM.get().createPrivateKey(Bytes32.fromHexString(hexKey));
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }

  static Dilithium3PrivateKey loadPQCPrivateKeyFromFile(final File file) {
    try {
      String hexPQCKey = readHexKey(file);
      return PQC_SIGNATURE_ALGORITHM.get().createPrivateKey(hexPQCKey);
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }

  static Dilithium3PublicKey loadPQCPublicKeyFromFile(final File file) {
    try {
      String hexPQCKey = readHexKey(file);
      return PQC_SIGNATURE_ALGORITHM.get().createPublicKey(hexPQCKey);
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }

  static SphincsPlusPrivateKey loadSphincsPrivateKeyFromFile(final File file) {
    try {
      String hexPQCKey = readHexKey(file);
      return SPHINCS_SIGNATURE_ALGORITHM.get().createPrivateKey(hexPQCKey);
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }

  static SphincsPlusPublicKey loadSphincsPublicKeyFromFile(final File file) {
    try {
      String hexPQCKey = readHexKey(file);
      return SPHINCS_SIGNATURE_ALGORITHM.get().createPublicKey(hexPQCKey);
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }

  static FalconPrivateKey loadFalconPrivateKeyFromFile(final File file) {
    try {
      String hexPQCKey = readHexKey(file);
      return FALCON_SIGNATURE_ALGORITHM.get().createPrivateKey(hexPQCKey);
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }

  static FalconPublicKey loadFalconPublicKeyFromFile(final File file) {
    try {
      String hexPQCKey = readHexKey(file);
      return FALCON_SIGNATURE_ALGORITHM.get().createPublicKey(hexPQCKey);
    } catch (IOException ex) {
      throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
    }
  }
  
  /**
   * Store key pair.
   *
   * @param keyPair the key pair
   * @param file the file
   * @throws IOException the io exception
   */
  static void storeKeyPair(final KeyPair keyPair, final File file) throws IOException {
    final File privateKeyDir = file.getParentFile();
    privateKeyDir.mkdirs();
    final Path tempPath = Files.createTempFile(privateKeyDir.toPath(), ".tmp", "");
    Files.write(
        tempPath,
        keyPair.getPrivateKey().getEncodedBytes().toString().getBytes(StandardCharsets.UTF_8));
    Files.move(tempPath, file.toPath(), REPLACE_EXISTING, ATOMIC_MOVE);
  }

  static void storeKeyPair(final Dilithium3KeyPair keyPair, final File file) throws IOException {
    final File privateKeyDir = file.getParentFile();
    privateKeyDir.mkdirs();
    final Path tempPath = Files.createTempFile(privateKeyDir.toPath(), ".tmp", "");
    Files.write(
        tempPath,
        keyPair.getPrivateKey().toString().getBytes(StandardCharsets.UTF_8));
    Files.move(tempPath, file.toPath(), REPLACE_EXISTING, ATOMIC_MOVE);
  }

  static void storeKeyPair(final SphincsPlusKeyPair keyPair, final File file) throws IOException {
    final File privateKeyDir = file.getParentFile();
    privateKeyDir.mkdirs();
    final Path tempPath = Files.createTempFile(privateKeyDir.toPath(), ".tmp", "");
    Files.write(
        tempPath,
        keyPair.getPrivateKey().toString().getBytes(StandardCharsets.UTF_8));
    Files.move(tempPath, file.toPath(), REPLACE_EXISTING, ATOMIC_MOVE);
  }

  static void storeKeyPair(final FalconKeyPair keyPair, final File file) throws IOException {
    final File privateKeyDir = file.getParentFile();
    privateKeyDir.mkdirs();
    final Path tempPath = Files.createTempFile(privateKeyDir.toPath(), ".tmp", "");
    Files.write(
        tempPath,
        keyPair.getPrivateKey().toString().getBytes(StandardCharsets.UTF_8));
    Files.move(tempPath, file.toPath(), REPLACE_EXISTING, ATOMIC_MOVE);
  }
}
