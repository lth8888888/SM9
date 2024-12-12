package com.IBE.test;

import com.IBE.operation.Main;
import com.IBE.gm.sm3.SM3;
import com.IBE.gm.sm4.SM4;
import com.IBE.gm.sm9.KGC;
import com.IBE.gm.sm9.KGCWithStandardTestKey;
import com.IBE.gm.sm9.MasterKeyPair;
import com.IBE.gm.sm9.PrivateKey;
import com.IBE.gm.sm9.PrivateKeyType;
import com.IBE.gm.sm9.SM9;
import com.IBE.gm.sm9.SM9Curve;
import com.IBE.gm.sm9.ResultEncapsulate;
import com.IBE.gm.sm9.ResultEncapsulateCipherText;
import com.IBE.gm.sm9.ResultCipherText;
import com.IBE.gm.sm9.ResultSignature;
import com.IBE.gm.sm9.SM9Utils;
import com.IBE.gm.sm9.SM9WithStandardTestKey;

import java.math.BigInteger;

public final class SM9_StandardTest {
    private SM9_StandardTest() {

    }

    public static void test() throws Exception {
        SM9Curve sm9Curve = new SM9Curve();
        Main.showMsg(sm9Curve.toString());

        KGC kgc = new KGC(sm9Curve);
        SM9 sm9 = new SM9(sm9Curve);

        kgc = new KGCWithStandardTestKey(sm9Curve);
        sm9 = new SM9WithStandardTestKey(sm9Curve);

        test_sm9_sign_standard(kgc, sm9);
        test_sm9_keyEncap_standard(kgc, sm9);
        test_sm9_encrypt_standard(kgc, sm9);
    }

    public static void test_sm9_keyEncap_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9密钥封装测试\n");

        String id_B = "ZJZ";

        Main.showMsg("加密主密钥和用户密钥产生过程中的相关值:");

        KGCWithStandardTestKey.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();
        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        int keyByteLen = 32;
        Main.showMsg("密钥封装的长度: " + keyByteLen + " bytes");

        Main.showMsg("密钥封装步骤A1-A7中的相关值:");
        SM9WithStandardTestKey.r = new BigInteger("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722", 16);
        ResultEncapsulate keyEncapsulation = sm9.keyEncapsulate(encryptMasterKeyPair.getPublicKey(), id_B, keyByteLen);

        Main.showMsg("解封装步骤B1-B4中的相关值:");
        ResultEncapsulateCipherText cipherText = ResultEncapsulateCipherText.fromByteArray(sm9.getCurve(), keyEncapsulation.getC().toByteArray());
        byte[] K = sm9.keyDecapsulate(encryptPrivateKey, id_B, keyByteLen, cipherText);

        if(SM9Utils.byteEqual(keyEncapsulation.getK(), K))
            Main.showMsg("测试成功");
        else
            Main.showMsg("测试失败");
    }

    public static void test_sm9_encrypt_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9加解密测试\n");

        String id_B = "ZJZ";
        String msg = "Solidity Based IBE System";

        Main.showMsg("加密主密钥和用户加密密钥产生过程中的相关值:");

        KGCWithStandardTestKey.k= new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        MasterKeyPair encryptMasterKeyPair = kgc.genEncryptMasterKeyPair();

        Main.showMsg("加密主私钥 ke:");
        Main.showMsg(encryptMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("加密主公钥 Ppub-e:");
        Main.showMsg(encryptMasterKeyPair.getPublicKey().toString());

        Main.showMsg("实体B的标识IDB:");
        Main.showMsg(id_B);
        Main.showMsg("IDB的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_B.getBytes()));

        PrivateKey encryptPrivateKey = kgc.genPrivateKey(encryptMasterKeyPair.getPrivateKey(), id_B, PrivateKeyType.KEY_ENCRYPT);
        Main.showMsg("加密私钥 de_B:");
        Main.showMsg(encryptPrivateKey.toString());

        Main.showMsg("待加密消息 M:");
        Main.showMsg(msg);
        Main.showMsg("M的16进制表示");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        Main.showMsg("消息M的长度: "+msg.length() + " bytes");
        Main.showMsg("K1_len: "+ SM4.KEY_BYTE_LENGTH + " bytes");

        int macKeyByteLen = SM3.DIGEST_SIZE;
        Main.showMsg("K2_len: "+ SM3.DIGEST_SIZE + " bytes");

        SM9WithStandardTestKey.r = new BigInteger("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C", 16);

        boolean isBaseBlockCipher = false;
        for(int i=0; i<2; i++)
        {
            Main.showMsg("");
            //if(isBaseBlockCipher)
            //Main.showMsg("加密明文的方法为分组密码算法 测试:");
            //else
            //Main.showMsg("加密明文的方法为基于KDF的序列密码 测试:");

            Main.showMsg("加密算法步骤A1-A8中的相关值:");
            ResultCipherText resultCipherText = sm9.encrypt(encryptMasterKeyPair.getPublicKey(), id_B, msg.getBytes(), isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("密文 C=C1||C3||C2:");
            Main.showMsg(SM9Utils.toHexString(resultCipherText.toByteArray()));

            Main.showMsg("");
            Main.showMsg("解密算法步骤B1-B5中的相关值:");
            byte[] msgd = sm9.decrypt(resultCipherText, encryptPrivateKey, id_B, isBaseBlockCipher, macKeyByteLen);
            Main.showMsg("解密后的明文M':");
            Main.showMsg(new String(msgd));

            if (SM9Utils.byteEqual(msg.getBytes(), msgd)) {
                Main.showMsg("加解密成功");
            } else {
                Main.showMsg("加解密失败");
            }

            isBaseBlockCipher = true;
        }
    }

    public static void test_sm9_sign_standard(KGC kgc, SM9 sm9) throws Exception {
        Main.showMsg("\n----------------------------------------------------------------------\n");
        Main.showMsg("SM9签名测试\n");

        String id_A = "YM";

        Main.showMsg("签名主密钥和用户签名私钥产生过程中的相关值:");

        //生成签名主密钥对
        KGCWithStandardTestKey.k= new BigInteger("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        MasterKeyPair signMasterKeyPair = kgc.genSignMasterKeyPair();
        Main.showMsg("签名主私钥 ks:");
        Main.showMsg(signMasterKeyPair.getPrivateKey().toString());
        Main.showMsg("签名主公钥 Ppub-s:");
        Main.showMsg(signMasterKeyPair.getPublicKey().toString());

        //显示ID信息
        Main.showMsg("实体A的标识IDA:");
        Main.showMsg(id_A);
        Main.showMsg("IDA的16进制表示");
        Main.showMsg(SM9Utils.toHexString(id_A.getBytes()));

        //生成签名私钥
        PrivateKey signPrivateKey = kgc.genPrivateKey(signMasterKeyPair.getPrivateKey(), id_A, PrivateKeyType.KEY_SIGN);
        Main.showMsg("签名私钥 ds_A:");
        Main.showMsg(signPrivateKey.toString());


        //签名
        Main.showMsg("签名步骤中的相关值:");
        String msg = "Solidity based IBE system";
        Main.showMsg("待签名消息 M:");
        Main.showMsg(msg);
        Main.showMsg("M的16进制表示");
        Main.showMsg(SM9Utils.toHexString(msg.getBytes()));
        SM9WithStandardTestKey.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        ResultSignature signature = sm9.sign(signMasterKeyPair.getPublicKey(), signPrivateKey, msg.getBytes());
        Main.showMsg("消息M的签名为(h,s):");
        Main.showMsg(signature.toString());


        //验签
        Main.showMsg("验证步骤中的相关值:");
        if(sm9.verify(signMasterKeyPair.getPublicKey(), id_A, msg.getBytes(), signature))
            Main.showMsg("verify OK");
        else
            Main.showMsg("verify failed");
    }
}
