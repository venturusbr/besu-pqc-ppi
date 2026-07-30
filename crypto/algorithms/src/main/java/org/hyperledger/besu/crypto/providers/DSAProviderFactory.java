package org.hyperledger.besu.crypto.providers;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.KeyConfiguration;

public class DSAProviderFactory {
  private static DigitalSignatureAlgorithmProvider nodeDsaProvider;

  public static NodeKeyProvider getNodeKeyProvider(){
    return nodeDsaProvider;
  }

  public static KeyManagementProvider getKeyManagementProvider(){
    return nodeDsaProvider;
  }

  public static VerifierProvider getVerifierProvider(){
    return nodeDsaProvider;
  }

  public static void setDsaProvider(final DigitalSignatureAlgorithmConfiguration dsaConfig, final KeyConfiguration keyConfig) {
    nodeDsaProvider = new DigitalSignatureAlgorithmProvider(dsaConfig, keyConfig);
  }

  /**
   * Returns the node's configured active {@link DigitalSignatureAlgorithm}, falling back to
   * {@link SignatureAlgorithmFactory#getInstance()} when no DSA provider has been configured
   * (e.g. in unit tests, which never call {@link #setDsaProvider}) or when a provider is present
   * but has no active DSA set. Never returns null.
   *
   * @return the active digital signature algorithm to use for consensus/node-key operations
   */
  public static DigitalSignatureAlgorithm getActiveDSA() {
    if (nodeDsaProvider == null) {
      return SignatureAlgorithmFactory.getInstance();
    }
    final DigitalSignatureAlgorithm activeDSA = nodeDsaProvider.getActiveDSA();
    return activeDSA != null ? activeDSA : SignatureAlgorithmFactory.getInstance();
  }
}
