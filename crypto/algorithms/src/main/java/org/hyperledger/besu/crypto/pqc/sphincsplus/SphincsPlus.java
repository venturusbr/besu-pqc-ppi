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
        SPHINCSPlusParameterSpec.haraka_128f,
        SPHINCSPlusParameterSpec.haraka_128f_simple,
        SPHINCSPlusParameterSpec.haraka_128s,
        SPHINCSPlusParameterSpec.haraka_128s_simple,
        SPHINCSPlusParameterSpec.haraka_192f,
        SPHINCSPlusParameterSpec.haraka_192f_simple,
        SPHINCSPlusParameterSpec.haraka_192s,
        SPHINCSPlusParameterSpec.haraka_192s_simple,
        SPHINCSPlusParameterSpec.haraka_256f,
        SPHINCSPlusParameterSpec.haraka_256f_simple,
        SPHINCSPlusParameterSpec.haraka_256s,
        SPHINCSPlusParameterSpec.haraka_256s_simple,
        SPHINCSPlusParameterSpec.sha2_128f,
        SPHINCSPlusParameterSpec.sha2_128f_robust,
        SPHINCSPlusParameterSpec.sha2_128s,
        SPHINCSPlusParameterSpec.sha2_128s_robust,
        SPHINCSPlusParameterSpec.sha2_192f,
        SPHINCSPlusParameterSpec.sha2_192f_robust,
        SPHINCSPlusParameterSpec.sha2_192s,
        SPHINCSPlusParameterSpec.sha2_192s_robust,
        SPHINCSPlusParameterSpec.sha2_256f,
        SPHINCSPlusParameterSpec.sha2_256f_robust,
        SPHINCSPlusParameterSpec.sha2_256s,
        SPHINCSPlusParameterSpec.sha2_256s_robust,
        SPHINCSPlusParameterSpec.shake_128f,
        SPHINCSPlusParameterSpec.shake_128f_robust,
        SPHINCSPlusParameterSpec.shake_128s,
        SPHINCSPlusParameterSpec.shake_128s_robust,
        SPHINCSPlusParameterSpec.shake_192f,
        SPHINCSPlusParameterSpec.shake_192f_robust,
        SPHINCSPlusParameterSpec.shake_192s,
        SPHINCSPlusParameterSpec.shake_192s_robust,
        SPHINCSPlusParameterSpec.shake_256f,
        SPHINCSPlusParameterSpec.shake_256f_robust,
        SPHINCSPlusParameterSpec.shake_256s,
        SPHINCSPlusParameterSpec.shake_256s_robust
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
    public String formatAlgorithmAndParameterTitle() {
        String parameterName =
            switch (SignatureAlgorithmFactory.getPqcParameterSpecIndex()) {
                case 0  -> "_haraka_128f";
                case 1  -> "_haraka_128f_simple";
                case 2  -> "_haraka_128s";
                case 3  -> "_haraka_128s_simple";
                case 4  -> "_haraka_192f";
                case 5  -> "_haraka_192f_simple";
                case 6  -> "_haraka_192s";
                case 7  -> "_haraka_192s_simple";
                case 8  -> "_haraka_256f";
                case 9  -> "_haraka_256f_simple";
                case 10 -> "_haraka_256s";
                case 11 -> "_haraka_256s_simple";
                case 12 -> "_sha2_128f";
                case 13 -> "_sha2_128f_simple";
                case 14 -> "_sha2_128s";
                case 15 -> "_sha2_128s_simple";
                case 16 -> "_sha2_192f";
                case 17 -> "_sha2_192f_simple";
                case 18 -> "_sha2_192s";
                case 19 -> "_sha2_192s_simple";
                case 20 -> "_sha2_256f";
                case 21 -> "_sha2_256f_simple";
                case 22 -> "_sha2_256s";
                case 23 -> "_sha2_256s_simple";
                case 24 -> "_shake_128f";
                case 25 -> "_shake_128f_simple";
                case 26 -> "_shake_128s";
                case 27 -> "_shake_128s_simple";
                case 28 -> "_shake_192f";
                case 29 -> "_shake_192f_simple";
                case 30 -> "_shake_192s";
                case 31 -> "_shake_192s_simple";
                case 32 -> "_shake_256f";
                case 33 -> "_shake_256f_simple";
                case 34 -> "_shake_256s";
                case 35 -> "_shake_256s_simple";
                default -> "_unknown";
            };
        return getAlgorithmName() + parameterName;
    }
}