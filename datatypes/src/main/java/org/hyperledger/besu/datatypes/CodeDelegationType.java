package org.hyperledger.besu.datatypes;

import java.util.Optional;

public enum CodeDelegationType {
    LEGACY((byte) 0x00),
    FLEXIBLE((byte) 0x01);

    private final byte serializedType;

    private static final CodeDelegationType[] codeDelegationTypeByOpaqueByte = new CodeDelegationType[256];

    CodeDelegationType(final byte serializedType){
        this.serializedType = serializedType;
    }

    static {
        for (CodeDelegationType type : values()) {
            codeDelegationTypeByOpaqueByte[Byte.toUnsignedInt(type.getSerializedType())] = type;
        }
    }

    public byte getSerializedType() {
        return serializedType;
    }

    public static Optional<CodeDelegationType> fromOpaque(final byte opaqueByte) {
        try{
            return Optional.ofNullable(codeDelegationTypeByOpaqueByte[Byte.toUnsignedInt(opaqueByte)]);
        } catch (final ArrayIndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }
}
