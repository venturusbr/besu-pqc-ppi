package org.hyperledger.besu.crypto.pqc.sphincsplus;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.pqc.PqcProvider;
import org.hyperledger.besu.crypto.pqc.PqcSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusKeyPair;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusPrivateKey;
import org.hyperledger.besu.crypto.pqc.sphincsplus.keys.SphincsPlusPublicKey;

public class SphincsPlus extends PqcSignatureAlgorithm{

    private final SPHINCSPlusParameterSpec[] SPHINCS_PLUS_PARAMETER_SPECS = {
                SPHINCSPlusParameterSpec.sha2_128f,
                SPHINCSPlusParameterSpec.sha2_128f_simple,
                SPHINCSPlusParameterSpec.sha2_128s,
                SPHINCSPlusParameterSpec.sha2_128s_simple,
                SPHINCSPlusParameterSpec.sha2_192f,
                SPHINCSPlusParameterSpec.sha2_192f_simple,
                SPHINCSPlusParameterSpec.sha2_192s,
                SPHINCSPlusParameterSpec.sha2_192s_simple,
                SPHINCSPlusParameterSpec.sha2_256f,
                SPHINCSPlusParameterSpec.sha2_256f_simple,
                SPHINCSPlusParameterSpec.sha2_256s,
                SPHINCSPlusParameterSpec.sha2_256s_simple,
                SPHINCSPlusParameterSpec.shake_128f,
                SPHINCSPlusParameterSpec.shake_128f_simple,
                SPHINCSPlusParameterSpec.shake_128s,
                SPHINCSPlusParameterSpec.shake_128s_simple,
                SPHINCSPlusParameterSpec.shake_192f,
                SPHINCSPlusParameterSpec.shake_192f_simple,
                SPHINCSPlusParameterSpec.shake_192s,
                SPHINCSPlusParameterSpec.shake_192s_simple,
                SPHINCSPlusParameterSpec.shake_256f,
                SPHINCSPlusParameterSpec.shake_256f_simple,
                SPHINCSPlusParameterSpec.shake_256s,
                SPHINCSPlusParameterSpec.shake_256s_simple
        };

    protected KeyPairGenerator keyPairGenerator;

    public SphincsPlus() {
        PqcProvider.initializeBouncyCastle();
    }

    public SphincsPlusKeyPair generateKeyPair() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("SPHINCSPlus");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        SphincsPlusKeyPair keyPair = SphincsPlusKeyPair.generate(keyPairGenerator, SPHINCS_PLUS_PARAMETER_SPECS[SignatureAlgorithmFactory.getPqcParameterSpecIndex()]);

        return keyPair;
    }

    public SphincsPlusKeyPair createSphincsPlusKeyPair(final SphincsPlusPrivateKey privateKey, final SphincsPlusPublicKey publicKey){
        return SphincsPlusKeyPair.createKeyPair(privateKey, publicKey);
    }

    public SphincsPlusPrivateKey createPrivateKey(final String hex){
        byte[] encoded = SphincsPlusPrivateKey.hexToBytes(hex);
        return SphincsPlusPrivateKey.create(encoded);
    }

    public SphincsPlusPublicKey createPublicKey(final String hex){
        byte[] encoded = SphincsPlusPublicKey.hexToBytes(hex);
        return SphincsPlusPublicKey.create(encoded);
    }

    @Override
    public String getAlgorithmName(){
        return "SPHINCSPlus";
    }
}