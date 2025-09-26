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
    private final NodeKeyFactory nodeKeyFactory;

    public KeyManager(final KeyConfiguration keyConfig) {
        this.keyConfig = keyConfig;
        this.nodeKeyFactory = new NodeKeyFactory(new KeyExtractor());
    }

    public void loadNodeKeyPairByPrivateKey(
            final PrivateKey sk,
            final DigitalSignatureAlgorithm activeDsa) {
        PublicKey pk = nodeKeyFactory.createPublicKey(sk, activeDsa.getDsaParametersSet());

        NodeKeyPair keyPair = nodeKeyFactory.createNodeKp(sk, pk);
        
        this.nodeKeyPair = keyPair;
    }

    public NodeKeyPair buildNodeKeyPair(
            final Bytes privateKeyBytes,
            final Bytes publicKeyBytes,
            final DSAParametersSet dsaParams) {
        PrivateKey sk = nodeKeyFactory.createPrivateKey(privateKeyBytes, dsaParams, PrivateKeyRepresentation.EXPANDED, PrivateKeyRepresentation.EXPANDED);

        PublicKey pk = nodeKeyFactory.createPublicKey(publicKeyBytes, dsaParams);

        return nodeKeyFactory.createNodeKp(sk, pk);
    }

    public PrivateKey loadPrivateKeyFromFile(final DSAParametersSet parametersSet){
        try{
            File skFile = keyConfig.getNodePrivateKeyFile();
            String hexKey = readHexKey(skFile);
            return nodeKeyFactory.createPrivateKey(Bytes.fromHexString(hexKey), parametersSet, keyConfig.getFirstKeyRepresentation(), keyConfig.getSecondKeyRepresentation());
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
