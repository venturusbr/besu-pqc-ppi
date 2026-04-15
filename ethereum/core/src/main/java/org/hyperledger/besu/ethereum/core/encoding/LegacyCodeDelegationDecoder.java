package org.hyperledger.besu.ethereum.core.encoding;

import java.math.BigInteger;
import java.util.function.Supplier;
import com.google.common.base.Suppliers;

import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.ethereum.core.CodeDelegation;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import org.apache.tuweni.bytes.Bytes;

public class LegacyCodeDelegationDecoder {
    private static final Supplier<SignatureAlgorithm> SIGNATURE_ALGORITHM =
      Suppliers.memoize(SignatureAlgorithmFactory::getInstance);
      
    public static CodeDelegation decode(final Bytes input){
        final RLPInput cdRlp = RLP.input(input);
        cdRlp.enterList();

        final BigInteger chainId = cdRlp.readBigIntegerScalar();
        final Address address = Address.wrap(cdRlp.readBytes());
        final long nonce = cdRlp.readLongScalar();

        final byte yParity = (byte) cdRlp.readUnsignedByteScalar();
        final BigInteger r = cdRlp.readUInt256Scalar().toUnsignedBigInteger();
        final BigInteger s = cdRlp.readUInt256Scalar().toUnsignedBigInteger();

        cdRlp.leaveList();

        final SECPSignature signature =
            SIGNATURE_ALGORITHM.get().createCodeDelegationSignature(r, s, yParity);

        return new CodeDelegation(chainId, address, nonce, signature);
    }
}
