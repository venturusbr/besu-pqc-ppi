package org.hyperledger.besu.crypto.pqc.keys;

public class PqcKeyPairSingleton {
    private static PqcKeyPair instance = null;

    private static PqcKeyPair createPqcKeypair(final String algorithmName) {
        System.out.println(algorithmName);
        PqcKeyPair keyPair = new PqcKeyPair();
        return keyPair;
    }

    public static PqcKeyPair getInstance(final String algorithmName) {
        if (instance == null) {
            instance = createPqcKeypair(algorithmName);
        }
        return instance;
    }
}
