package org.hyperledger.besu.crypto.pqc.falcon;
import org.hyperledger.besu.crypto.pqc.PqcSignature;

public class FalconSignature extends PqcSignature{
    @Override
    protected String getSignatureName(){
        return "Falcon";
    }
}
