package com.IBE.gm.sm9;

import java.io.ByteArrayOutputStream;

import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;


public class MasterPublicKey {
    CurveElement Q;
    boolean isSignKey;

    public MasterPublicKey(CurveElement point, boolean isSignKey)
    {
        this.Q = point;
        this.isSignKey = isSignKey;
    }


    public static MasterPublicKey fromByteArray(SM9Curve curve, byte[] source) {
        boolean isSignKey = false;
        if(source[0]!=0)
            isSignKey = true;

        CurveElement Q;
        if(isSignKey)
            Q = curve.G2.newElement();
        else
            Q = curve.G1.newElement();
        Q.setFromBytes(source, 1);

        return new MasterPublicKey(Q, isSignKey);
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        if(isSignKey)
            bos.write(1);
        else
            bos.write(0);

        byte[] temp = Q.toBytes();

        bos.write(temp, 0, temp.length);

        return bos.toByteArray();
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();

        //sb.append("sm9 master public key:");
        sb.append(SM9Utils.NEW_LINE);

        if(isSignKey)
            sb.append(SM9Utils.toHexString(SM9Utils.G2ElementToByte(Q)));
        else
            sb.append(SM9Utils.toHexString(SM9Utils.G1ElementToBytes(Q)));

        return sb.toString();
    }
}
