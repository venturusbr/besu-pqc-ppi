package org.hyperledger.besu.crypto.pqc.falcon;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.hyperledger.besu.crypto.pqc.PqcProvider;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconKeyPair;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPrivateKey;
import org.hyperledger.besu.crypto.pqc.falcon.keys.FalconPublicKey;
import org.hyperledger.besu.nativelib.secp256r1.Signature;

public class Falcon extends PqcSignatureAlgorithm{

    protected KeyPairGenerator keyPairGenerator;

    FalconParameterSpec[] falconParameterSpecs = {
                FalconParameterSpec.falcon_512,
                FalconParameterSpec.falcon_1024
        };

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

    @Override
    public String getAlgorithmName(){
        return "Falcon";
    }
    
}
