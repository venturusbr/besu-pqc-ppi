package org.hyperledger.besu.crypto.config;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import com.google.common.collect.ImmutableMap;

public class DigitalSignatureAlgorithmConfiguration {
    private final SupportedAlgorithms supportedAlgorithms;
    private DigitalSignatureAlgorithm nodeActiveDSA;
    private ImmutableMap<Short, DigitalSignatureAlgorithm> accountsEnabledDSAs = ImmutableMap.of();

    public DigitalSignatureAlgorithmConfiguration(){
        this.supportedAlgorithms = new SupportedAlgorithms();
        this.nodeActiveDSA = null;
    }

    public void setNodeActiveDSA(final String algorithmName) throws InvalidAlgorithmParameterException{
        DigitalSignatureAlgorithm maybeDsa = supportedAlgorithms.getDSA(algorithmName);

        if(maybeDsa == null){
            throw new InvalidAlgorithmParameterException("Algorithm name provided is not supported");
        }

        this.nodeActiveDSA = maybeDsa;
    }

    public DigitalSignatureAlgorithm getActiveDSA(){
        return nodeActiveDSA;
    }

    public void buildAccountSupportedAlgorithms(final List<DSAParametersSet> selectedAccountDSAs) throws InvalidAlgorithmParameterException{

        final ImmutableMap.Builder<Short, DigitalSignatureAlgorithm> builder =
            ImmutableMap.builder();

        for (final DSAParametersSet param : selectedAccountDSAs) {
            if(supportedAlgorithms.supports(param.getName())){
                builder.put(param.getId(), supportedAlgorithms.getDSA(param.getName()));
                continue;
            }
            throw new InvalidAlgorithmParameterException("Algorithm name provided is not supported");
        }

        this.accountsEnabledDSAs = builder.build();
    }

    public DigitalSignatureAlgorithm getEnabledDSA(final Short dsaId){
        return accountsEnabledDSAs.get(dsaId);
    }
}
