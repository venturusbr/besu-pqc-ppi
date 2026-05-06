package org.hyperledger.besu.crypto.key;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;

public class KeyManager {
    private final KeyConfiguration keyConfig;
    private NodeKeyPair nodeKeyPair;

    public KeyManager(final KeyConfiguration keyConfig) {
        this.keyConfig = keyConfig;
    }

    public void loadNodeKeyPairByPrivateKey(
            final PrivateKey sk,
            final DigitalSignatureAlgorithm activeDsa) {
        PublicKey pk = KeyFactory.createPublicKey(sk, activeDsa.getDsaParametersSet());

        NodeKeyPair keyPair = KeyFactory.createNodeKp(sk, pk);
        
        this.nodeKeyPair = keyPair;
    }

    public NodeKeyPair buildNodeKeyPair(
            final Bytes privateKeyBytes,
            final Bytes publicKeyBytes,
            final DSAParametersSet dsaParams) {
        PrivateKey sk = KeyFactory.createPrivateKey(privateKeyBytes, dsaParams, PrivateKeyRepresentation.EXPANDED, PrivateKeyRepresentation.EXPANDED);

        PublicKey pk = KeyFactory.createPublicKey(sk, dsaParams);

        return KeyFactory.createNodeKp(sk, pk);
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
