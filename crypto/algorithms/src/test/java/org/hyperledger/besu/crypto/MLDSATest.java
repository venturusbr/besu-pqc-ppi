package org.hyperledger.besu.crypto;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.NodeKeyPair;
import org.hyperledger.besu.crypto.signature.Signature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MLDSATest {

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testGenerateNodeKeyPair(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        NodeKeyPair keyPair = mldsa.generateNodeKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testSignAndVerify(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        NodeKeyPair keyPair = mldsa.generateNodeKeyPair();

        PrivateKey sk = keyPair.getPrivateKey();
        PublicKey pk = keyPair.getPublicKey();

        Bytes message = Bytes.wrap("mensagem de teste".getBytes(UTF_8));

        Signature signature = mldsa.sign(message, sk);
        assertNotNull(signature);

        boolean isValid = mldsa.verify(message, signature, pk);
        assertTrue(isValid, "Assinatura deveria ser válida");
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testVerifyFailsForModifiedMessage(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        NodeKeyPair keyPair = mldsa.generateNodeKeyPair();

        PrivateKey sk = keyPair.getPrivateKey();
        PublicKey pk = keyPair.getPublicKey();

        Bytes message = Bytes.wrap("mensagem original".getBytes(UTF_8));
        Bytes modified = Bytes.wrap("mensagem alterada".getBytes(UTF_8));

        Signature signature = mldsa.sign(message, sk);

        boolean isValid = mldsa.verify(modified, signature, pk);
        assertFalse(isValid, "Assinatura não deve ser válida para mensagem alterada");
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testGetDsaParametersSet(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        assertEquals(params, mldsa.getDsaParametersSet());
    }
}
