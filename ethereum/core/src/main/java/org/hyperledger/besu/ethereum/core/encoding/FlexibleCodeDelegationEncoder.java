package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import org.apache.tuweni.bytes.Bytes;

public class FlexibleCodeDelegationEncoder {
    public static void encode(final CodeDelegation codeDelegation, final RLPOutput out, final Boolean includeSignature){
        out.startList();
        out.writeByte(codeDelegation.getType().getSerializedType());
        out.writeShort(codeDelegation.dsaType().orElseThrow());
        LegacyCodeDelegationEncoder.encodeAuthorizationDetails(codeDelegation, out);
        out.writeBytes(Bytes.wrap(codeDelegation.maybePublicKey().get().getEncoded()));
        if(includeSignature){
            TransactionSignatureEncoder.writeSignatureBytes(codeDelegation.signature(), out);
        }
        out.endList();
    }
}
