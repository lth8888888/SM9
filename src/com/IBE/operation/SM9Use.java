package com.IBE.operation;

import com.IBE.gm.sm3.SM3;
import com.IBE.gm.sm4.SM4;
import com.IBE.gm.sm9.KGC;

import com.IBE.gm.sm9.MasterKeyPair;
import com.IBE.gm.sm9.MasterPrivateKey;
import com.IBE.gm.sm9.MasterPublicKey;
import com.IBE.gm.sm9.PrivateKey;
import com.IBE.gm.sm9.PrivateKeyType;
import com.IBE.gm.sm9.SM9;
import com.IBE.gm.sm9.ResultKeyExchange;
import com.IBE.gm.sm9.SM9Curve;
import com.IBE.gm.sm9.ResultEncapsulate;
import com.IBE.gm.sm9.ResultEncapsulateCipherText;
import com.IBE.gm.sm9.G1KeyPair;
import com.IBE.gm.sm9.ResultCipherText;
import com.IBE.gm.sm9.ResultSignature;
import com.IBE.gm.sm9.SM9Utils;
import com.IBE.gm.sm9.SM9WithStandardTestKey;

import java.math.BigInteger;
import java.util.Scanner;

public final class SM9Use {
    private SM9Use() {

    }

//    public static void test() throws Exception {
//        SM9Curve sm9Curve = new SM9Curve();
//        Main.showMsg(sm9Curve.toString());
//
//        KGC kgc = new KGC(sm9Curve);
//        SM9 sm9 = new SM9(sm9Curve);
//
//        test_sm9_sign(kgc, sm9);
//        test_sm9_keyEncap(kgc, sm9);
//        test_sm9_encrypt(kgc, sm9);
//    }

    public static masterKey test_sm9_masterKeyEncap(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9主密钥生成\n");
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());
        masterKey i = new masterKey();
        i.setMasterPublicKey(encryptMasterKeyPair.getPublicKey().toString());
        i.setMasterPrivateKey(encryptMasterKeyPair.getPrivateKey().toString());
        return i;
    }

    public static String test_sm9_normalKeyEncap(KGC kgc, SM9 sm9, String id) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9用户密钥生成\n");
        String id_B = id;

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());


        Main.showMsg("实体标识: ");
        Main.showMsg(id);
        String temp = "";
        String time = temp + System.currentTimeMillis();
        ibeDao.change_vId(id, time);
        id_B = id + time;
        Main.showMsg("加入时间信息后的实体标识:");
        Main.showMsg(id_B);



        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());
        return encryptPrivateKey.toString();
    }

    public static String test_sm9_keyEncap(KGC kgc, SM9 sm9, String id) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9用户密钥生成\n");
        String id_B = id;

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        String prk = encryptMasterKeyPair.getPrivateKey().toString();
        Main.showMsg(prk);
        Main.showMsg("加密主公钥 Ppub-e:");
        String pk = encryptMasterKeyPair.getPublicKey().toString();
        Main.showMsg(pk);

        masterKey i = new masterKey();
        i.setMasterPublicKey(pk);
        i.setMasterPrivateKey(prk);
        ibeDao.masterUserKeyUpdate(id, i);

        Main.showMsg("实体的标识ID:");
        Main.showMsg(id_B);

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());
        return encryptPrivateKey.toString();
    }

    public static void test_sm9_encrypt(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9加解密测试\n");

        String id_B = "ZJZ";
        String msg = "Solidity Based IBE System";

        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("待加密消息 M:");
        Main.showMsg(msg);
        Main.showMsg("消息M的长度: " + msg.length() + " bytes");
        Main.showMsg("K1_len: " + SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
        Main.showMsg("K2_len: " + SM3.DIGEST_SIZE + " bytes");

        boolean isBaseBlockCipher = false;
        //for(int i=0; i<2; i++)
        //{
        Main.showMsg("");
        if (isBaseBlockCipher)
            Main.showMsg("加密明文的方法为分组密码算法 测试:");
        else
            Main.showMsg("加密明文的方法为基于KDF的序列密码 测试:");

        ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
        Main.showMsg("加密后的密文 C=C1||C3||C2:");
        Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));

        Main.showMsg("");
        byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
        Main.showMsg("解密后的明文M':");
        Main.showMsg(new String(msgd));

        if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
            Main.showMsg("加解密成功");
        } else {
            Main.showMsg("加解密失败");
        }

        //isBaseBlockCipher = true;
        //}
    }

    public static void test_sm9_sign(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9签名测试\n");

        String id_A = "YM";

        //生成签名主密钥对
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("签名主私钥 ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("签名主公钥 Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());

        //显示ID信息
        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(id_A);

        //生成签名私钥
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("签名私钥 ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //签名
        Main.showMsg("签名步骤中的相关值:");
        String msg = "Solidity Based IBE System";
        Main.showMsg("待签名消息 M:");
        Main.showMsg(msg);

        ResultSignature signature = sm9.sign(signMasterKeyPair.getPublicKey(), signPrivateKey, msg.getBytes());
        Main.showMsg("消息M的签名为(h,s):");
        Main.showMsg(signature.toString());

        //验签
        if (sm9.verify(signMasterKeyPair.getPublicKey(), id_A, msg.getBytes(), signature))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }

}
