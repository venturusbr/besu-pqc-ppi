package org.hyperledger.besu.crypto.keyexchange.config;

import org.hyperledger.besu.crypto.keyexchange.KeyEstablishmentSchemeType;

public class KeyExchangeConfiguration {
    private boolean isHybridMode = false;
    private String handshakerType = KeyEstablishmentSchemeType.TRADITIONAL_ECIES;

    public static KeyExchangeConfiguration create() {
        return new KeyExchangeConfiguration();
    }

    public KeyExchangeConfiguration setHandshakerType(final String handshakerType) {
        if(KeyEstablishmentSchemeType.schemeIsSupported(handshakerType)){
            this.handshakerType = handshakerType;
            setIsHybridMode();
        }
        return this;
    }

    private void setIsHybridMode(){
        this.isHybridMode = KeyEstablishmentSchemeType.isHybridScheme(handshakerType);
    }

    public boolean getIsHybridMode() {
        return isHybridMode;
    }

    public String getHandshakerType() {
        return handshakerType;
    }
}
