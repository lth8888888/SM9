package com.IBE.operation;

public class masterKey {
    private String masterPublicKey;
    private String masterPrivateKey;

    public masterKey() {
    }

    public String getMasterPublicKey() {
        return masterPublicKey;
    }

    public void setMasterPublicKey(String masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    public String getMasterPrivateKey() {
        return masterPrivateKey;
    }

    public void setMasterPrivateKey(String masterPrivateKey) {
        this.masterPrivateKey = masterPrivateKey;
    }

    @Override
    public String toString() {
        return "masterKey{" +
                "masterPublicKey='" + masterPublicKey + '\'' +
                ", masterPrivateKey='" + masterPrivateKey + '\'' +
                '}';
    }
}
