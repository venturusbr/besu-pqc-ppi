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

    /**
     * The delegation list as it enters a transaction's signing preimage. It is not the wire layout
     * (see {@link #encodeCodeDelegationWire}), and changing it would invalidate every transaction
     * already signed.
     */
    public static void encodeCodeDelegationInner(
      final List<CodeDelegation> payloads, final RLPOutput rlpOutput) {
        rlpOutput.startList();
        payloads.forEach(payload -> encodeOpaqueBytes(payload, rlpOutput));
        rlpOutput.endList();
    }

    /**
     * The delegation list as it travels inside an encoded transaction, which is what
     * {@link CodeDelegationDecoder#decodeRLP} reads back: a legacy delegation as a bare RLP list, a
     * typed one as a single byte string holding its type byte and the RLP list of its fields.
     */
    public static void encodeCodeDelegationWire(
      final List<CodeDelegation> payloads, final RLPOutput rlpOutput) {
        rlpOutput.startList();
        payloads.forEach(payload -> {
            final CodeDelegationType type = getType(payload);
            if (CodeDelegationType.LEGACY.equals(type)) {
                LegacyCodeDelegationEncoder.encode(payload, rlpOutput, true);
            } else {
                rlpOutput.writeBytes(FlexibleCodeDelegationEncoder.encodeWire(payload));
            }
        });
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
