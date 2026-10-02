package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleCodeDelegationEncoder {
    public static void encode(final CodeDelegation codeDelegation, final RLPOutput out, final Boolean includeSignature){
        out.startList();
        out.writeByte(codeDelegation.getType().getSerializedType());
        out.writeShort(codeDelegation.dsaType().orElseThrow());
        LegacyCodeDelegationEncoder.encodeAuthorizationDetails(codeDelegation, out);
        // A delegation whose key is recovered whole from its signature carries no key, and the
        // decoder reads none back for it.
        codeDelegation.maybePublicKey().ifPresent(
            publicKey -> PublicKeyEncoder.encodeByDsaId(publicKey, codeDelegation.dsaType().get(), out));
        if(includeSignature){
            TransactionSignatureEncoder.writeSignatureBytes(codeDelegation.signature(), out);
        }
        out.endList();
    }
}
