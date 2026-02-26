package org.hyperledger.besu.crypto.providers;

public class DSAAlgorithmProviderFactory {
  private static DigitalSignatureAlgorithmProvider dsaProvider;

  public static DigitalSignatureAlgorithmProvider getDsaProvider() {
    return dsaProvider;
  }

  public static void setDsaProvider(final DigitalSignatureAlgorithmProvider provider) {
    DSAAlgorithmProviderFactory.dsaProvider = provider;
  }
}
