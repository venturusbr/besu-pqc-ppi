package org.hyperledger.besu.ethereum.core.encoding;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegationType;
import org.hyperledger.besu.ethereum.core.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

public class FlexibleCodeDelegationDecoder {
    public static CodeDelegation decode(final Bytes input){
        final RLPInput cdRlp = RLP.input(input.slice(1)); // Skip the code delegation type byte
        cdRlp.enterList();
        final CodeDelegationType type = CodeDelegationType.FLEXIBLE;
        final Optional<Short> dsaType = Optional.ofNullable(cdRlp.readShort());
        final DSAParametersSet dsaParams = DSAParametersSet.fromId(dsaType.get());
        final BigInteger chainId = cdRlp.readBigIntegerScalar();
        final Address address = Address.wrap(cdRlp.readBytes());
        final long nonce = cdRlp.readLongScalar();
        final Optional<PublicKey> maybePk =
        Optional.ofNullable(
            cdRlp.readBytes(pkBytes ->
                pkBytes.isEmpty() ? null : KeyFactory.createPublicKey(pkBytes, dsaParams)
            )
        );

        final Signature signature = cdRlp.readBytes(signatureBytes -> SignatureFactory.createSignatureFromBytes(signatureBytes, dsaParams));

        cdRlp.leaveList();

        return new CodeDelegation(type, dsaType, chainId, address, nonce, maybePk,signature);
    }
}
