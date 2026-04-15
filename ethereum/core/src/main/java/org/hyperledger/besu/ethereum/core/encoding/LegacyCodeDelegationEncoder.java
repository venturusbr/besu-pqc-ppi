package org.hyperledger.besu.ethereum.core.encoding;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

public class LegacyCodeDelegationEncoder {
    public static void encodeAuthorizationDetails(
      final CodeDelegation payload, final RLPOutput rlpOutput) {
        rlpOutput.writeBigIntegerScalar(payload.chainId());
        rlpOutput.writeBytes(payload.address().getBytes().copy());
        rlpOutput.writeLongScalar(payload.nonce());
    }

    public static void encode(final CodeDelegation payload, final RLPOutput rlpOutput, final Boolean includeSignature){
        rlpOutput.startList();
        encodeAuthorizationDetails(payload, rlpOutput);
        if(includeSignature){
            SECPSignature secpSignature = (SECPSignature) payload.signature();
            rlpOutput.writeUnsignedByte(secpSignature.getRecId() & 0xFF);
            rlpOutput.writeBigIntegerScalar(secpSignature.getR());
            rlpOutput.writeBigIntegerScalar(secpSignature.getS());
        }
        rlpOutput.endList();
    }
}
