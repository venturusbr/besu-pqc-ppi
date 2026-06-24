package org.hyperledger.besu.crypto.config;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

public class DigitalSignatureAlgorithmConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(DigitalSignatureAlgorithmConfiguration.class);
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

        LOG.info(
            "Account-enabled DSAs: {}",
            accountsEnabledDSAs.keySet().stream()
                .map(DSAParametersSet::fromId)
                .map(DSAParametersSet::getName)
                .collect(Collectors.joining(", "))
        );
    }

    public DigitalSignatureAlgorithm getEnabledDSA(
            final Short dsaId) {
        return accountsEnabledDSAs.get(dsaId).get();
    }

    public List<String> getAccountsSupportedDSANames() {
        return accountsEnabledDSAs.keySet().stream()
            .map(DSAParametersSet::fromId)
            .map(DSAParametersSet::getName)
            .collect(Collectors.toList());
    }
}