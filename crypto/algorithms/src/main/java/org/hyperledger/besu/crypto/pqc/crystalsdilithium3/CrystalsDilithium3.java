package org.hyperledger.besu.crypto.pqc.crystalsdilithium3;

import org.hyperledger.besu.crypto.pqc.PqcProvider;

public class CrystalsDilithium3 extends AbstractCrystalsDilithium3{
    public CrystalsDilithium3(){
        PqcProvider.initializeBouncyCastle();
    }
}
