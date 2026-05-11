package org.hyperledger.besu.cli.converter;


import java.util.Arrays;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import picocli.CommandLine;

public class DSAParametersSetConverter
    implements CommandLine.ITypeConverter<DSAParametersSet> {

  @Override
  public DSAParametersSet convert(final String value) {

    return Arrays.stream(DSAParametersSet.values())
        .filter(v -> v.getName().equalsIgnoreCase(value))
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Unsupported DSA algorithm: " + value));
  }
}
