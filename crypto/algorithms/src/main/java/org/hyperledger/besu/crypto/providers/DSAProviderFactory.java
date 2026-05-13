package org.hyperledger.besu.crypto.providers;

public class DSAProviderFactory {
  private static DigitalSignatureAlgorithmProvider nodeDsaProvider;

  public static DigitalSignatureAlgorithmProvider getDsaProvider() {
    return nodeDsaProvider;
  }

  public static void setDsaProvider(final DigitalSignatureAlgorithmProvider provider) {
    DSAProviderFactory.nodeDsaProvider = provider;
  }
}
