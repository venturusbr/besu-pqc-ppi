package org.hyperledger.besu.crypto.keyexchange;

import java.util.Set;

public class KeyEstablishmentSchemeType {
    public static final String PLAIN = "PLAIN";
    public static final String TRADITIONAL_ECIES = "ECIES";
    public static final String PQ_TRADITIONAL_ECIES_MLKEM = "ECIES-MLKEM";

    public static final Set<String> NON_HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES = Set.of(TRADITIONAL_ECIES, PLAIN);
    public static final Set<String> HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES = Set.of(PQ_TRADITIONAL_ECIES_MLKEM);

    public static boolean schemeIsSupported(final String schemeName){
        return NON_HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES.contains(schemeName) ||
        HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES.contains(schemeName);
    }

    public static boolean isHybridScheme(final String schemeName){
        return HYBRID_SUPPORTED_KEY_ESTABLISHMENT_SCHEMES.contains(schemeName);
    }
}
