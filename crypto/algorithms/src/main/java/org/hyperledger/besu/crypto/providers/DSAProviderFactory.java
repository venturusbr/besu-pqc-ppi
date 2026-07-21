package org.hyperledger.besu.crypto.providers;

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
}
