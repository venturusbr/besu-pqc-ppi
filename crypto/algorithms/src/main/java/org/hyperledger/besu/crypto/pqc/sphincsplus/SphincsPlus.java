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
        SPHINCSPlusParameterSpec parameter = SPHINCS_PLUS_PARAMETER_SPECS[SignatureAlgorithmFactory.getPqcParameterSpecIndex()];

        generateKeyPairLog();

        SphincsPlusKeyPair keyPair = SphincsPlusKeyPair.generate(keyPairGenerator, parameter);

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
    @Override
    public String formatAlgorithmAndParameterTitle(){
        String parameterName =
        switch (SignatureAlgorithmFactory.getPqcParameterSpecIndex()) {
            case 0 -> "_sha2_128f";
            case 1 -> "_sha2_128f_simple";
            case 2 -> "_sha2_128s";
            case 3 -> "_sha2_128s_simple";
            case 4 -> "_sha2_192f";
            case 5 -> "_sha2_192f_simple";
            case 6 -> "_sha2_192s";
            case 7 -> "_sha2_192s_simple";
            case 8 -> "_sha2_256f";
            case 9 -> "_sha2_256f_simple";
            case 10 -> "_sha2_256s";
            case 11 -> "_sha2_256s_simple";
            case 12 -> "_shake_128f";
            case 13 -> "_shake_128f_simple";
            case 14 -> "_shake_128s";
            case 15 -> "_shake_128s_simple";
            case 16 -> "_shake_192f";
            case 17 -> "_shake_192f_simple";
            case 18 -> "_shake_192s";
            case 19 -> "_shake_192s_simple";
            case 20 -> "_shake_256f";
            case 21 -> "_shake_256f_simple";
            case 22 -> "_shake_256s";
            case 23 -> "_shake_256s_simple";
            default -> "_512";
        };
        return getAlgorithmName() + parameterName;
    }
}