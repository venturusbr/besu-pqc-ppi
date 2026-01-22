package org.hyperledger.besu.crypto.pqc.sphincsplus;

import org.hyperledger.besu.crypto.pqc.PqcSignature;


public class SphincsPlusSignature extends PqcSignature{
    @Override
    protected String getSignatureName(){
        return "SPHINCSPlus";
    }
}
