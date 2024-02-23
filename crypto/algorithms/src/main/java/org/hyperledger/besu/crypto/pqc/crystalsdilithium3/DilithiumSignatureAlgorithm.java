package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3KeyPair;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PrivateKey;
import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.keys.Dilithium3PublicKey;

public interface DilithiumSignatureAlgorithm {
    public Dilithium3KeyPair generateKeyPair();

    public Dilithium3KeyPair createDilithium3KeyPair(Dilithium3PrivateKey privateKey, Dilithium3PublicKey publicKey);

    public CrystalsDilithiumSignature sign(byte[] secpSignatureEncoded, PrivateKey privateKeyPQC);

    public boolean verify(PublicKey publicKey, byte[] dataToSign, byte[] signature);

    public Dilithium3PrivateKey createPrivateKey(String hex);

    public Dilithium3PublicKey createPublicKey(String hex);
}
