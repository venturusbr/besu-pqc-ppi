package org.hyperledger.besu.crypto.pqc.falcon;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.hyperledger.besu.crypto.pqc.PqcProvider;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconKeyPair;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPrivateKey;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPublicKey;

public class Falcon {

    protected KeyPairGenerator keyPairGenerator;

    FalconParameterSpec[] falconParameterSpecs = {
                FalconParameterSpec.falcon_512,
                FalconParameterSpec.falcon_1024
        };

    public Falcon() {
        PqcProvider.initializeBouncyCastle();
    }

    public FalconKeyPair generateKeyPair() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("Falcon");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        FalconKeyPair keyPair = FalconKeyPair.generate(keyPairGenerator, falconParameterSpecs[1]);

        return keyPair;
    }

    public FalconKeyPair createFalconKeyPair(final FalconPrivateKey privateKey, final FalconPublicKey publicKey){
        return FalconKeyPair.createKeyPair(privateKey, publicKey);
    }

    public FalconPrivateKey createPrivateKey(final String hex){
        byte[] encoded = FalconPrivateKey.hexToBytes(hex);
        return FalconPrivateKey.create(encoded);
    }

    public FalconPublicKey createPublicKey(final String hex){
        byte[] encoded = FalconPublicKey.hexToBytes(hex);
        return FalconPublicKey.create(encoded);
    }

    public FalconSignature sign(final byte[] secpSignatureEncoded, final PrivateKey privateKey) {
        return FalconSignature.create(secpSignatureEncoded, privateKey);
    }
    
}
