package org.hyperledger.besu.crypto.key.types;

import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class MLDSAPrivateKey implements PrivateKey{
    private final String algorithmName;
    private final Bytes encoded;
    private final String format;

    private MLDSAPrivateKey(final String algorithmName, final Bytes encoded, final String format){
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

    public static MLDSAPrivateKey create(final Bytes skBytes, final DSAParametersSet dsaParametersSet){
        if(skBytes.size() == dsaParametersSet.getSeedLength()){
            return createFromSeed(skBytes.toArrayUnsafe(), dsaParametersSet);
        }
        return new MLDSAPrivateKey(dsaParametersSet.getName(), skBytes, "RAW");
    }
    private static MLDSAPrivateKey createFromSeed(final byte[] seed, final DSAParametersSet dsaParametersSet){
        MLDSAParameters mldsaParams = MLDSA.getBCMLDSAParametersByDSAParameterName(dsaParametersSet.getName());
        MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(mldsaParams, seed);
        return new MLDSAPrivateKey(dsaParametersSet.getName(), Bytes.wrap(skParams.getEncoded()), "RAW");
    }
}
