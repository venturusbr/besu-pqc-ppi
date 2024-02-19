package org.hyperledger.besu.crypto.pqc;

import java.security.Security;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class PqcProvider {
    private static boolean isInitialized = false;

    public static void initializeBouncyCastle(){
        if(!isInitialized){
            if (Security.getProvider("BCPQC") == null) {
                Security.addProvider(new BouncyCastlePQCProvider());
                isInitialized = true;
            }
        }
    }
}
