package org.hyperledger.besu.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivateKey;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyExtractor;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class KeyExtractorTest {
    private static PrivateKey expectedPrivateKeyMLDSA44;
    private static PrivateKey expectedPrivateKeyMLDSA65;
    private static PrivateKey expectedPrivateKeyMLDSA87;
    private static PrivateKey expectedPrivateKeySECP256K1;
    private static String seedString;
    private static KeyExtractor keyExtractor;

    @BeforeAll
    static void setUp(){
        try {
            keyExtractor = new KeyExtractor();
            expectedPrivateKeyMLDSA44 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validMLDSA44PrivateKey.txt", DSAParametersSet.MLDSA44);

            expectedPrivateKeyMLDSA65 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validMLDSA65PrivateKey.txt", DSAParametersSet.MLDSA65);

            expectedPrivateKeyMLDSA87 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validMLDSA87PrivateKey.txt", DSAParametersSet.MLDSA87);

            expectedPrivateKeySECP256K1 = TestKeyLoader.loadPrivateKey("/org/hyperledger/besu/crypto/validPrivateKey.txt", DSAParametersSet.SECP256K1);

            seedString = TestKeyLoader.loadSeed("/org/hyperledger/besu/crypto/validMLDSASeed.txt");
        } catch (URISyntaxException | IOException e) {
            fail("Failed to read file" + e.getMessage());
        }
    }

    @Test
    void extractSeedBySeedLength(){
        DSAParametersSet mldsaParams = DSAParametersSet.MLDSA44;
        DSAParametersSet secpParams = DSAParametersSet.SECP256K1;

        Bytes hybridSecpMLDSAKeyBytes = Bytes.fromHexString(getPrivateKeySECP256K1MLDSAseed());

        Bytes skMldsa = keyExtractor.extractPrivateKeyBytesAtOffset(hybridSecpMLDSAKeyBytes, secpParams.getPrivateKeyLength() + 1, mldsaParams, PrivateKeyRepresentation.SEED);

        String actualSeed = TestKeyLoader.bytesToHex(skMldsa.toArrayUnsafe());

        System.err.println("Actual: " + actualSeed + "length: " + actualSeed.length());
        System.err.println("Expected: " + expectedPrivateKeyMLDSA44 + "length: " + expectedPrivateKeyMLDSA44.getEncoded().length);
        assertEquals(seedString, actualSeed);
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void extractMLDSASecondExpandedKeys(final DSAParametersSet params){
        DSAParametersSet secpParametersSet = DSAParametersSet.SECP256K1;
        Bytes hybridSecpMLDSAKeyBytes;
        switch (params) {
            case MLDSA44:
                hybridSecpMLDSAKeyBytes = Bytes.fromHexString(getPrivateKeySECP256K1MLDSA44());

                String mldsa44Key = extractSecondKey(hybridSecpMLDSAKeyBytes, secpParametersSet, params, PrivateKeyRepresentation.EXPANDED);
        
                System.err.println("Actual: " + mldsa44Key);
                System.err.println("Expected: " + expectedPrivateKeyMLDSA44);
                assertEquals(TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA44.getEncoded()), mldsa44Key);
                break;
            case MLDSA65:
                hybridSecpMLDSAKeyBytes = Bytes.fromHexString(getPrivateKeySECP256K1MLDSA65());

                String mldsa65Key = extractSecondKey(hybridSecpMLDSAKeyBytes, secpParametersSet, params, PrivateKeyRepresentation.EXPANDED);
        
                System.err.println("Actual: " + mldsa65Key);
                System.err.println("Expected: " + expectedPrivateKeyMLDSA65);
                assertEquals(TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA65.getEncoded()), mldsa65Key);
                break;
            case MLDSA87:
                hybridSecpMLDSAKeyBytes = Bytes.fromHexString(getPrivateKeySECP256K1MLDSA87());

                String mldsa87Key = extractSecondKey(hybridSecpMLDSAKeyBytes, secpParametersSet, params, PrivateKeyRepresentation.EXPANDED);
        
                System.err.println("Actual: " + mldsa87Key);
                System.err.println("Expected: " + expectedPrivateKeyMLDSA87);
                assertEquals(TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA87.getEncoded()), mldsa87Key);
                break;
            default:
                hybridSecpMLDSAKeyBytes = null;
                break;
        }
    }

    private String extractSecondKey(final Bytes hybridKey, final DSAParametersSet firstParams, final DSAParametersSet secondParams, PrivateKeyRepresentation skRep){
        Bytes secondSk = keyExtractor.extractPrivateKeyBytesAtOffset(hybridKey, firstParams.getPrivateKeyLength() + 1, secondParams, skRep);
        return TestKeyLoader.bytesToHex(secondSk.toArrayUnsafe());
    }

    private static String getPrivateKeySECP256K1MLDSAseed(){
        return TestKeyLoader.bytesToHex(expectedPrivateKeySECP256K1.getEncoded()) + seedString;
    }

    private static String getPrivateKeySECP256K1MLDSA44(){
        return TestKeyLoader.bytesToHex(expectedPrivateKeySECP256K1.getEncoded()) + TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA44.getEncoded());
    }

    private static String getPrivateKeySECP256K1MLDSA65(){
        return TestKeyLoader.bytesToHex(expectedPrivateKeySECP256K1.getEncoded()) + TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA65.getEncoded());
    }

    private static String getPrivateKeySECP256K1MLDSA87(){
        return TestKeyLoader.bytesToHex(expectedPrivateKeySECP256K1.getEncoded()) + TestKeyLoader.bytesToHex(expectedPrivateKeyMLDSA87.getEncoded());
    }
}
