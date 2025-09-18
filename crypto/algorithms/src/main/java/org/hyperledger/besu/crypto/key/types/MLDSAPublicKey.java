package org.hyperledger.besu.crypto.key.types;

import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class MLDSAPublicKey implements PublicKey{
    private final String algorithmName;
    private final Bytes encoded;
    private final String format;

    public MLDSAPublicKey(final String algorithmName, final Bytes encoded, final String format){
        this.algorithmName = algorithmName;
        this.format = format;
        this.encoded = encoded;
    }

    @Override
    public String getAlgorithm(){
        return algorithmName;
    }

    @Override
    public String getFormat(){
        return format;
    }

    @Override
    public byte[] getEncoded(){
        return encoded.toArrayUnsafe();
    }

    public static PublicKey deriveMLDSAPkFromSk(final Bytes skBytes, final DSAParametersSet dsaParametersSet){
        MLDSAParameters mldsaParams = MLDSA.getBCMLDSAParametersByDSAParameterName(dsaParametersSet.getName());
        MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(mldsaParams, skBytes.toArrayUnsafe());
        MLDSAPublicKeyParameters pkParams = skParams.getPublicKeyParameters();

        return create(Bytes.wrap(pkParams.getEncoded()), dsaParametersSet);
    }

    public static PublicKey create(final Bytes pkBytes, final DSAParametersSet dsaParametersSet){
        return new MLDSAPublicKey(dsaParametersSet.getName(), pkBytes, "RAW");
    }
}
