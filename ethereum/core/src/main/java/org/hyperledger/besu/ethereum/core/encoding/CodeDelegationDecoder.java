package org.hyperledger.besu.ethereum.core.encoding;

import static com.google.common.base.Preconditions.checkNotNull;

import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

public class CodeDelegationDecoder {
    @FunctionalInterface
    interface Decoder {
        CodeDelegation decode(Bytes input);
    }

    private static CodeDelegation decodeCodeDelegation(final RLPInput rlpInput){
        final Bytes codeDelegationBytes = rlpInput.readBytes();

        CodeDelegationType type = 
            getCodeDelegationType(codeDelegationBytes)
                .orElseThrow((() -> new IllegalArgumentException("Unsupported transaction type")));
        return decodeCodeDelegation(codeDelegationBytes, type);
    }

    private static final EnumMap<CodeDelegationType, Decoder> CODE_DELEGATION_DECODERS = new EnumMap<>(
        Map.of(
            CodeDelegationType.LEGACY,
            LegacyCodeDelegationDecoder::decode,
            CodeDelegationType.FLEXIBLE,
            FlexibleCodeDelegationDecoder::decode
        )
    );

    public static CodeDelegation decodeRLP(final RLPInput rlpInput){
        if(isTypedCodeDelegation(rlpInput)){
            return decodeCodeDelegation(rlpInput);
        } else {
            // A legacy delegation is written as a bare RLP list, so it has to be read in place as
            // a list. Reading it as a byte string throws "current item is a list".
            return LegacyCodeDelegationDecoder.decode(rlpInput);
        }
    }

    private static Optional<CodeDelegationType> getCodeDelegationType(final Bytes opaqueBytes) {
        byte codeDelegationTypeByte = opaqueBytes.get(0);
        return CodeDelegationType.fromOpaque(codeDelegationTypeByte);
    }

    private static CodeDelegation decodeCodeDelegation(
        final Bytes codeDelegationBytes,
        final CodeDelegationType type
    ){
        return getDecoder(type).decode(codeDelegationBytes);
    }

    public static CodeDelegation decodeOpaqueBytes(final Bytes opaqueBytes){
        if(opaqueBytes.isEmpty()){
            throw new IllegalArgumentException("Empty opaque bytes");
        }
        Optional<CodeDelegationType> type = getCodeDelegationType(opaqueBytes);
        if(type.isPresent()){
            return decodeCodeDelegation(opaqueBytes, type.get());
        } else {
            return decodeRLP(RLP.input(opaqueBytes));
        }
    }

    private static boolean isTypedCodeDelegation(final RLPInput rlpInput){
        return !rlpInput.nextIsList();
    }

    private static Decoder getDecoder(
        final CodeDelegationType type
    ){
        return checkNotNull(
            CODE_DELEGATION_DECODERS.get(type),
            "Developer Error. A supported code delegation type %s has no associated decoding logic",
            type
        );
    }
}
