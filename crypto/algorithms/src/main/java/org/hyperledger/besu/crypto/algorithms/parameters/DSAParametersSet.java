package org.hyperledger.besu.crypto.algorithms.parameters;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public enum DSAParametersSet {
    SECP256K1((short) 0x0001,"SECP256K1", 32, 64, 65, null),
    SECP256R1((short) 0x0002, "SECP256R1", 32, 64, 65, null),
    MLDSA44((short) 0x0030, "MLDSA44", 2560, 1312, 2420, 32),
    MLDSA65((short) 0x0031, "MLDSA65", 4032, 1952, 3309, 32),
    MLDSA87((short) 0x0032, "MLDSA87", 4896, 2592, 4627, 32),
    // Private key is f || g || F || h (see Falcon512PrivateKey). No fixed signature length:
    // Falcon signatures are variable-length, so they cannot be cut out of a concatenation at a
    // fixed offset. A hybrid must place Falcon last and take the remainder instead.
    FALCON512((short) 0x0040, "FALCON512", 2176, 896, null, null),
    SECP256K1MLDSA44((short) 0x0060, "SECP256K1-MLDSA44", 2592, 1376, 2485, null),
    // SECP256K1 (fixed-length) first, Falcon-512 (variable-length) last: see SignatureFactory.
    SECP256K1FALCON512((short) 0x0061, "SECP256K1-FALCON512", 2208, 960, null, null)
    ;

    private final Short id;
    private final String name;
    private final Integer publicKeyLength;
    private final Integer privateKeyLength;
    private final Integer signatureLength;
    private final Integer seedLength;

    private static final Map<Short, DSAParametersSet> BY_ID =
        Arrays.stream(values())
              .collect(Collectors.toMap(DSAParametersSet::getId, e -> e));

    private static final Map<String, DSAParametersSet> BY_NAME =
        Arrays.stream(values())
            .collect(Collectors.toMap(DSAParametersSet::getName, e -> e));

    DSAParametersSet(final Short id, final String name, final Integer privateKeyLength, final Integer publicKeyLength,
            final Integer signatureLength, final Integer seedLength) {
        this.id = id;
        this.name = name;
        this.publicKeyLength = publicKeyLength;
        this.privateKeyLength = privateKeyLength;
        this.signatureLength = signatureLength;
        this.seedLength = seedLength;
    }

    public static DSAParametersSet fromName(final String name) {
        DSAParametersSet set = BY_NAME.get(name);
        if (set == null) {
            throw new IllegalArgumentException("Unknown DSAParametersSet name: " + name);
        }
        return set;
    }

    public static DSAParametersSet fromId(final Short id) {
        DSAParametersSet set = BY_ID.get(id);
        if (set == null) {
            throw new IllegalArgumentException("Unknown DSAParametersSet id: " + id);
        }
        return set;
    }

    public Short getId() {
        return id;
    }

    public String getName(){
        return name;
    }

    public Integer getPublicKeyLength(){
        return publicKeyLength;
    }

    public Integer getPrivateKeyLength(){
        return privateKeyLength;
    }

    public Integer getSignatureLength(){
        return signatureLength;
    }

    public Integer getSeedLength(){
        return seedLength;
    }
}
