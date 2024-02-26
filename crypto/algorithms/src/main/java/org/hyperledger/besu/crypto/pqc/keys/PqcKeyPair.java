package org.hyperledger.besu.crypto.pqc.keys;

import java.security.PrivateKey;
import java.security.PublicKey;

public class PqcKeyPair {
    private static PrivateKey privKey = null;
    private static PublicKey pubKey = null;

    public static void setKeys(final PrivateKey privateKey, final PublicKey publicKey){
        if(privKey == null){
            privKey = privateKey;
        }
        if(pubKey == null){
            pubKey = publicKey;
        }
    }

    public static PrivateKey getPrivKey(){
        return privKey;
    }

    public static PublicKey getPubKey(){
        return pubKey;
    }
}
