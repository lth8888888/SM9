package com.IBE.operation;

public class ibeTable {
    private int Id;
    private String PublicKey;
    private String PrivateKey;
    private String Password;
    private int UserLevel;

    public ibeTable() {
    }

    public int getId() {
        return Id;
    }

    public void setId(int id) {
        Id = id;
    }

    public String getPublicKey() {
        return PublicKey;
    }

    public void setPublicKey(String publicKey) {
        PublicKey = publicKey;
    }

    public String getPrivateKey() {
        return PrivateKey;
    }

    public void setPrivateKey(String privateKey) {
        PrivateKey = privateKey;
    }

    public String getPassword() {
        return Password;
    }

    public void setPassword(String password) {
        Password = password;
    }

    public int getLevel() {
        return UserLevel;
    }

    public void setLevel(int level) {
        UserLevel = level;
    }

    @Override
    public String toString() {
        return "ibeTable{" +
                "Id=" + Id +
                ", PublicKey='" + PublicKey + '\'' +
                ", PrivateKey='" + PrivateKey + '\'' +
                ", Password='" + Password + '\'' +
                ", UserLevel=" + UserLevel +
                '}';
    }
}
