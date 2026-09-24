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
      
    /**
     * Decodes a legacy code delegation from {@code input}, which must hold the RLP encoding of the
     * delegation list and nothing else.
     */
    public static CodeDelegation decode(final Bytes input){
        return decode(RLP.input(input));
    }

    /**
     * Decodes a legacy code delegation in place from the supplied input, consuming exactly the
     * delegation's list. Legacy delegations are written directly as an RLP list with no type byte
     * (see {@link LegacyCodeDelegationEncoder#encode}), so when they appear as elements of a
     * delegation list they must be read as a list rather than as an opaque byte string.
     */
    public static CodeDelegation decode(final RLPInput cdRlp){
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
