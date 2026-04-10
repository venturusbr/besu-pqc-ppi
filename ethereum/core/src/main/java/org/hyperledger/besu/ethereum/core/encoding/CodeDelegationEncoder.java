package org.hyperledger.besu.ethereum.core.encoding;

import java.util.List;

import org.bouncycastle.util.Bytes;
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import static com.google.common.base.Preconditions.checkNotNull;
import com.google.common.collect.ImmutableMap;

public class CodeDelegationEncoder {
    @FunctionalInterface
    interface Encoder {
        void encode(CodeDelegation codeDelegation, RLPOutput out, Boolean includeSignature);
    }

    private static final ImmutableMap<CodeDelegationType, Encoder> ENCODERS =
      ImmutableMap.of(
        CodeDelegationType.LEGACY,
        LegacyCodeDelegationEncoder::encode,
        CodeDelegationType.FLEXIBLE,
        FlexibleCodeDelegationEncoder::encode
    );

    public static void encodeCodeDelegationInner(
      final List<CodeDelegation> payloads, final RLPOutput rlpOutput) {
        rlpOutput.startList();
        payloads.forEach(payload -> encodeOpaqueBytes(payload, rlpOutput));
        rlpOutput.endList();
    }

    public static void encodeWithoutSignature(final CodeDelegation codeDelegation, final RLPOutput out){
        final CodeDelegationType type = getType(codeDelegation);

        final Encoder encoder = getEncoder(type);

        if(!CodeDelegationType.LEGACY.equals(type)){
            out.writeByte(type.getSerializedType());
        }

        encoder.encode(codeDelegation, out, false);
    }
    
    public static void encodeOpaqueBytes(final CodeDelegation codeDelegation, final RLPOutput out) {

        final CodeDelegationType type = getType(codeDelegation);

        final Encoder encoder = getEncoder(type);

        if(!CodeDelegationType.LEGACY.equals(type)){
            out.writeByte(type.getSerializedType());
        }

        encoder.encode(codeDelegation, out, true);
    }

    private static CodeDelegationType getType(final CodeDelegation codeDelegation) {
        return checkNotNull(
            codeDelegation.getType(),
            "CodeDelegation type was not specified."
        );
    }

    private static Encoder getEncoder(final CodeDelegationType type) {
        return checkNotNull(
            ENCODERS.get(type),
            "No encoder for type %s",
            type
        );
    }
}
