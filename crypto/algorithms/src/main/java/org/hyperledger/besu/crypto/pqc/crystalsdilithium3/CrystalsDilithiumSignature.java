package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import org.hyperledger.besu.crypto.pqc.PqcSignature;

public class CrystalsDilithiumSignature extends PqcSignature{
    @Override
    protected String getSignatureName(){
        return "Dilithium";
    }
}
