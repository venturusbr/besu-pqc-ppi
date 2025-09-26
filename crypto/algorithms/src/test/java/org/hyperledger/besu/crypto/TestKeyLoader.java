package org.hyperledger.besu.crypto;


import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.util.List;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;

public final class TestKeyLoader {
    private static final KeyManager keyManager = new KeyManager(new KeyConfiguration(null, null, null));

    public static PrivateKey loadPrivateKey(final String resourcePath, final DSAParametersSet params) throws URISyntaxException {
        return keyManager.loadPrivateKeyFromFile(
            new File(TestKeyLoader.class.getResource(resourcePath).toURI()),
            params
        );
    }

    public static String loadSeed(final String resourcePath) throws IOException, URISyntaxException {
        List<String> lines = Files.readAllLines(
            new File(TestKeyLoader.class.getResource(resourcePath).toURI()).toPath()
        );
        if (lines.size() != 1) {
            throw new IllegalArgumentException("Seed inválida");
        }
        return lines.get(0);
    }


    public static String bytesToHex(final byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
