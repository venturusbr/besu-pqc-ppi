package org.hyperledger.besu.crypto.pqc;

import java.security.PrivateKey;
import java.util.function.Supplier;

import org.hyperledger.besu.crypto.pqc.crystalsdilithium3.CrystalsDilithiumSignature;
import org.hyperledger.besu.crypto.pqc.falcon.FalconSignature;
import org.hyperledger.besu.crypto.pqc.sphincsplus.SphincsPlusSignature;

import com.google.common.collect.ImmutableMap;

public class PqcSignatureFactory {
    private static final ImmutableMap<String, Supplier<PqcSignature>> PQC_SUPPORTED_SIGNATURE_ALGORITHMS = ImmutableMap
      .of("Dilithium", CrystalsDilithiumSignature::new,"SPHINCSPlus",SphincsPlusSignature::new, "Falcon", FalconSignature::new);

    public static PqcSignature createSignature(PrivateKey privateKey, byte[] dataToSign, String algorithmName){
        PqcSignature pqcSignature = PQC_SUPPORTED_SIGNATURE_ALGORITHMS.get(algorithmName).get();
        pqcSignature.create(dataToSign, privateKey);
        return pqcSignature;
    }
}
