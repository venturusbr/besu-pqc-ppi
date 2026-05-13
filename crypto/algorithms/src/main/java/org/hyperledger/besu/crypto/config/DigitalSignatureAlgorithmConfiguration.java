package org.hyperledger.besu.crypto.config;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.function.Supplier;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import com.google.common.collect.ImmutableMap;

public class DigitalSignatureAlgorithmConfiguration {
    private final SupportedAlgorithms supportedAlgorithms;
    private DigitalSignatureAlgorithm nodeActiveDSA;
    private ImmutableMap<Short, Supplier<DigitalSignatureAlgorithm>> accountsEnabledDSAs;

    public DigitalSignatureAlgorithmConfiguration() {
        this.supportedAlgorithms = new SupportedAlgorithms();
        this.nodeActiveDSA = null;
    }

    public void setNodeActiveDSA(final String algorithmName)
            throws InvalidAlgorithmParameterException {

        if (!supportedAlgorithms.supports(algorithmName)) {
            throw new InvalidAlgorithmParameterException(
                "Algorithm name provided is not supported");
        }

        this.nodeActiveDSA = supportedAlgorithms.getDSA(algorithmName).get();
    }

    public DigitalSignatureAlgorithm getActiveDSA() {
        return nodeActiveDSA;
    }

    public void buildAccountSupportedAlgorithms(
            final List<DSAParametersSet> selectedAccountDSAs)
            throws InvalidAlgorithmParameterException {

        final ImmutableMap.Builder<Short, Supplier<DigitalSignatureAlgorithm>>
            builder = ImmutableMap.builder();

        for (final DSAParametersSet param : selectedAccountDSAs) {
            if (supportedAlgorithms.supports(param.getName())) {
                builder.put(
                    param.getId(),
                    supportedAlgorithms.getDSA(param.getName()));
                continue;
            }

            throw new InvalidAlgorithmParameterException(
                "Algorithm name provided is not supported");
        }

        this.accountsEnabledDSAs = builder.build();
    }

    public DigitalSignatureAlgorithm getEnabledDSA(
            final Short dsaId) {
        return accountsEnabledDSAs.get(dsaId).get();
    }
}