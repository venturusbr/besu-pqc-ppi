package org.hyperledger.besu.crypto.algorithms;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.NodeKeyPair;
import org.hyperledger.besu.crypto.key.NodeKeyPairFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

public class MLDSA implements DigitalSignatureAlgorithm{
    private static final Map<String, MLDSAParameters> RENAMING_TO_LIB = new HashMap<>();
    private DSAParametersSet mldsaParameters;
    private MLDSASigner signerAndVerifier;
    private MLDSAParameters selectedBCParameter;

    static {
        RENAMING_TO_LIB.put(DSAParametersSet.MLDSA44.getName(), MLDSAParameters.ml_dsa_44);
        RENAMING_TO_LIB.put(DSAParametersSet.MLDSA65.getName(), MLDSAParameters.ml_dsa_65);
        RENAMING_TO_LIB.put(DSAParametersSet.MLDSA87.getName(), MLDSAParameters.ml_dsa_87);
    }

    public MLDSA(final DSAParametersSet mldsaParameters){
        Security.addProvider(new BouncyCastlePQCProvider());
        this.mldsaParameters = mldsaParameters;
        this.signerAndVerifier = new MLDSASigner();
        this.selectedBCParameter = RENAMING_TO_LIB.get(mldsaParameters.getName());
    }

    @Override
    public Signature sign(final Bytes data, final PrivateKey sk) {
        MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(selectedBCParameter, sk.getEncoded());
        signerAndVerifier.init(true, skParams);
        signerAndVerifier.update(data.toArrayUnsafe(), 0, data.size());

        byte[] signature = null;
        try {
            signature = signerAndVerifier.generateSignature();
        } catch (DataLengthException | CryptoException e) {
            e.printStackTrace();
        }
        return SignatureFactory.createSingleSignatureFromBytes(signature, sk.getAlgorithm());
    }

    @Override
    public Boolean verify(final Bytes data, final Signature signature, final PublicKey pk) {
        MLDSAPublicKeyParameters pkParams = new MLDSAPublicKeyParameters(selectedBCParameter, pk.getEncoded());
        signerAndVerifier.init(false, pkParams);
        signerAndVerifier.update(data.toArrayUnsafe(), 0, data.size());

        return signerAndVerifier.verifySignature(signature.encodedBytes().toArrayUnsafe());
    }

    @Override
    public NodeKeyPair generateKeyPair() {
        MLDSAKeyPairGenerator mldsaKpGenerator = new MLDSAKeyPairGenerator();
        KeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(), selectedBCParameter);

        mldsaKpGenerator.init(genParams);
        AsymmetricCipherKeyPair mldsaKp = mldsaKpGenerator.generateKeyPair();

        MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) mldsaKp.getPrivate();
        MLDSAPublicKeyParameters pk = (MLDSAPublicKeyParameters) mldsaKp.getPublic();

        Bytes rawSk = Bytes.wrap(sk.getEncoded());
        Bytes rawPk = Bytes.wrap(pk.getEncoded());

        NodeKeyPair kp = NodeKeyPairFactory.create(rawSk, rawPk, mldsaParameters.getName());

        return kp;
    }

    @Override
    public DSAParametersSet getDsaParametersSet() {
        return mldsaParameters;
    }

    // private Bytes deserializeMLDSAPrivateKey(final PrivateKey sk) throws IOException{
    //     AsymmetricKeyParameter skParams = PrivateKeyFactory.createKey(sk.getEncoded());
    //     byte[] rawSk = ((MLDSAPrivateKeyParameters) skParams).getEncoded();
    //     return Bytes.wrap(rawSk);
    // }

    // private Bytes deserializeMLDSAPublicKey(final PublicKey pk) throws IOException{
    //     AsymmetricKeyParameter pkParam = PublicKeyFactory.createKey(pk.getEncoded());
    //     byte[] rawPk = ((MLDSAPublicKeyParameters) pkParam).getEncoded(); 
    //     return Bytes.wrap(rawPk);
    // }
}
