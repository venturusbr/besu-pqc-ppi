package org.hyperledger.besu.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class MLDSAPrivateKeyTest {
    private static PrivateKey expectedPrivateKeyMLDSA44;
    private static PrivateKey expectedPrivateKeyMLDSA65;
    private static PrivateKey expectedPrivateKeyMLDSA87;
    private static String seedString;

    @BeforeAll
    static void setUp(){
        try {
            expectedPrivateKeyMLDSA44 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validMLDSA44PrivateKey.txt", DSAParametersSet.MLDSA44, null, null);

            expectedPrivateKeyMLDSA65 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validMLDSA65PrivateKey.txt", DSAParametersSet.MLDSA65, null, null);

            expectedPrivateKeyMLDSA87 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validMLDSA87PrivateKey.txt", DSAParametersSet.MLDSA87, null, null);

            seedString = TestKeyLoader.loadSeed("/org/hyperledger/besu/crypto/validMLDSASeed.txt");
        } catch (URISyntaxException | IOException e) {
            fail("Failed to read file" + e.getMessage());
        }
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void derivePrivateKeyFromSeed(final DSAParametersSet params) { 
        Bytes seedBytes = Bytes.fromHexString(seedString);

        MLDSAPrivateKey privateKey = MLDSAPrivateKey.create(seedBytes, params);

        assertNotNull(privateKey);
        assertEquals(params.getName(), privateKey.getAlgorithm());
        assertEquals("RAW", privateKey.getFormat());
        assertTrue(privateKey.getEncoded().length > 0);

        byte[] actualKey = privateKey.getEncoded();

        switch (params) {
            case MLDSA44:
                assertEquals(TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA44.getEncoded()), TestKeyLoader.bytesToHex(actualKey));
                break;
            case MLDSA65:
                assertEquals(TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA65.getEncoded()), TestKeyLoader.bytesToHex(actualKey));
                break;
            case MLDSA87:
                assertEquals(TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA87.getEncoded()), TestKeyLoader.bytesToHex(actualKey));
                break;
            default:
                break;
        }
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void createPrivateKeyFromExpandedSk(final DSAParametersSet params) {
        switch (params) {
            case MLDSA44:
                MLDSAPrivateKey privateKeyMLDSA44 = MLDSAPrivateKey.create(Bytes.wrap(expectedPrivateKeyMLDSA44.getEncoded()), params);
                byte[] skMLDSA44 = privateKeyMLDSA44.getEncoded();
                assertEquals(expectedPrivateKeyMLDSA44.getEncoded(), skMLDSA44);
                break;
            case MLDSA65:
                MLDSAPrivateKey privateKeyMLDSA65 = MLDSAPrivateKey.create(Bytes.wrap(expectedPrivateKeyMLDSA65.getEncoded()), params);
                byte[] skMLDSA65 = privateKeyMLDSA65.getEncoded();
                assertEquals(expectedPrivateKeyMLDSA65.getEncoded(), skMLDSA65);
                break;
            case MLDSA87:
                MLDSAPrivateKey privateKeyMLDSA87 = MLDSAPrivateKey.create(Bytes.wrap(expectedPrivateKeyMLDSA87.getEncoded()), params);
                byte[] skMLDSA87 = privateKeyMLDSA87.getEncoded();
                assertEquals(expectedPrivateKeyMLDSA87.getEncoded(), skMLDSA87);
                break;
            default:
                break;
        }
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void MLDSAPrivateKeyAttributes(final DSAParametersSet params) {
        byte[] originalBytes = "encoded data".getBytes(UTF_8);
        Bytes bytesWrapped = Bytes.wrap(originalBytes);

        PrivateKey privateKey = MLDSAPrivateKey.create(bytesWrapped, params);

        assertEquals(params.getName(), privateKey.getAlgorithm());

        assertEquals("RAW", privateKey.getFormat());

        byte[] encodedBytes = privateKey.getEncoded();
        assertNotNull(encodedBytes);
        assertArrayEquals(originalBytes, encodedBytes);
    }
}