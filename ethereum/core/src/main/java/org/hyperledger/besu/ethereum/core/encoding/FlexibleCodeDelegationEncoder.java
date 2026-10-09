package org.hyperledger.besu.ethereum.core.encoding;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class FlexibleCodeDelegationEncoder {
    /**
     * The layout the delegation's signing hash is computed over. It is not the wire layout (see
     * {@link #encodeWire}), and changing it would invalidate every delegation already signed.
     */
    public static void encode(final CodeDelegation codeDelegation, final RLPOutput out, final Boolean includeSignature){
        out.startList();
        out.writeByte(codeDelegation.getType().getSerializedType());
        writeFields(codeDelegation, out, includeSignature);
        out.endList();
    }

    /**
     * The delegation as it travels inside a transaction: the type byte followed by the RLP list of
     * its fields, the way {@link FlexibleCodeDelegationDecoder} reads it back. The caller writes the
     * result as a single RLP byte string.
     */
    public static Bytes encodeWire(final CodeDelegation codeDelegation){
        final Bytes fields = RLP.encode(out -> {
            out.startList();
            writeFields(codeDelegation, out, true);
            out.endList();
        });
        return Bytes.concatenate(Bytes.of(codeDelegation.getType().getSerializedType()), fields);
    }

    private static void writeFields(final CodeDelegation codeDelegation, final RLPOutput out, final Boolean includeSignature){
        out.writeShort(codeDelegation.dsaType().orElseThrow());
        LegacyCodeDelegationEncoder.encodeAuthorizationDetails(codeDelegation, out);
        // A delegation whose key is recovered whole from its signature carries no key, and the
        // decoder reads none back for it.
        codeDelegation.maybePublicKey().ifPresent(
            publicKey -> PublicKeyEncoder.encodeByDsaId(publicKey, codeDelegation.dsaType().get(), out));
        if(includeSignature){
            TransactionSignatureEncoder.writeSignatureBytes(codeDelegation.signature(), out);
        }
    }
}
