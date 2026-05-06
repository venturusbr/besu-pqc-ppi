package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleCodeDelegationEncoder {
    public static void encode(final CodeDelegation codeDelegation, final RLPOutput out, final Boolean includeSignature){
        out.startList();
        out.writeByte(codeDelegation.getType().getSerializedType());
        out.writeShort(codeDelegation.dsaType().orElseThrow());
        LegacyCodeDelegationEncoder.encodeAuthorizationDetails(codeDelegation, out);
        PublicKeyEncoder.encodeByDsaId(codeDelegation.maybePublicKey().get(), codeDelegation.dsaType().get(), out);
        if(includeSignature){
            TransactionSignatureEncoder.writeSignatureBytes(codeDelegation.signature(), out);
        }
        out.endList();
    }
}
