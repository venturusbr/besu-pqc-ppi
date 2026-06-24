package org.hyperledger.besu.crypto.key;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;

public class KeyManager {
    private final KeyConfiguration keyConfig;
    private KeyPair nodeKeyPair;

    public KeyManager(final KeyConfiguration keyConfig) {
        this.keyConfig = keyConfig;
    }

    public void loadOrGenerateNodeKeyPair(final DigitalSignatureAlgorithm activeDsa) {
        try {
            PrivateKey sk = loadPrivateKeyFromFile(activeDsa.getDsaParametersSet());
            loadNodeKeyPairByPrivateKey(sk, activeDsa);
        } catch (IllegalArgumentException e) {
            this.nodeKeyPair = activeDsa.generateNodeKeyPair();
        }
    }

    public void loadNodeKeyPairByPrivateKey(
            final PrivateKey sk,
            final DigitalSignatureAlgorithm activeDsa) {
        PublicKey pk = KeyFactory.createPublicKey(sk, activeDsa.getDsaParametersSet());

        KeyPair keyPair = KeyFactory.createKeyPair(sk, pk);
        
        this.nodeKeyPair = keyPair;
    }

    public PrivateKey loadPrivateKeyFromFile(final DSAParametersSet parametersSet){
        try{
            File skFile = keyConfig.getNodePrivateKeyFile();
            String hexKey = readHexKey(skFile);
            return KeyFactory.createPrivateKey(Bytes.fromHexString(hexKey), parametersSet, keyConfig.getFirstKeyRepresentation(), keyConfig.getSecondKeyRepresentation());
        } catch(IOException ex) {
            throw new IllegalArgumentException("Supplied file does not contain valid private key.");
        }
    }

    private String readHexKey(final File file) throws IOException {
        final List<String> info = Files.readAllLines(file.toPath());
        if(info.size() != 1){
            throw new IllegalArgumentException("Supplied file does not contain valid keyPair pair.");
        }
        return info.get(0);
    }

    public PrivateKey getNodePrivateKey() {
        return nodeKeyPair.getPrivateKey();
    }

    public PublicKey getNodePublicKey() {
        return nodeKeyPair.getPublicKey();
    }
}
