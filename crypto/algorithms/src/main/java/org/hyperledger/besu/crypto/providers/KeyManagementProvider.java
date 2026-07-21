package org.hyperledger.besu.crypto.providers;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public interface KeyManagementProvider {
    KeyPair generateKeyPair(final DSAParametersSet dsaParams);
    void loadNodeKeyPair();
}
