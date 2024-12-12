package com.IBE.operation;

import com.IBE.gm.sm9.KGC;
import com.IBE.gm.sm9.SM9;
import com.IBE.gm.sm9.SM9Curve;

import java.util.Scanner;

public class Main {
    public static void showMsg(String msg) {
        System.out.println(msg);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("------------欢迎进入IBE管理系统------------");
        System.out.println("----------------请输入选项----------------");
        System.out.println("1: 管理员登录");
        System.out.println("2: 非监管用户登录");
        System.out.println("3: 受监管用户登录");
        System.out.println("4: 退出");
        Scanner s = new Scanner(System.in);
        int choice1 = s.nextInt();
        loopAll:
        switch (choice1) {
            case 1:
                System.out.println("请输入管理员身份: ");
                String admin = s.next();
                if (ibeDao.judgeLevel(admin) != 1) {
                    System.out.println("用户名错误或权限不足，系统退出");
                    break loopAll;
                }
                System.out.println("请输入管理员密码: ");
                String aPass = s.next();
                if (ibeDao.Registered(admin)) {
                        while (!ibeDao.PasswordCheck(admin, aPass)) {
                            System.out.println("密码错误，请重新输入: ");
                            String aPass1 = s.next();
                            if (ibeDao.PasswordCheck(admin, aPass1)) {
                                break;
                            }
                        }
                        System.out.println("登录成功!");
                        while (true) {
                            System.out.println("------------管理员功能界面------------");
                            System.out.println("--------------请输入选项--------------");
                            System.out.println("1: 生成主公私钥对");
                            System.out.println("2: 更新主公私钥对");
                            System.out.println("3: 指定用户更新密钥");
                            System.out.println("4: 指定用户信息查询");
                            System.out.println("5: 指定用户身份撤销");
                            System.out.println("6: 管理员密码修改");
                            System.out.println("7: 用户身份注册");
                            System.out.println("8: 退出");
                            int choice2 = s.nextInt();
                            switch (choice2) {
                                case 1:
                                    SM9Curve sm9Curve = new SM9Curve();
                                    Main.showMsg(sm9Curve.toString());
                                    KGC kgc = new KGC(sm9Curve);
                                    SM9 sm9 = new SM9(sm9Curve);
                                    masterKey i = SM9Use.test_sm9_masterKeyEncap(kgc, sm9);
                                    ibeDao.masterKey(i);
                                    break;
                                case 2:
                                    SM9Curve sm9Curve3 = new SM9Curve();
                                    Main.showMsg(sm9Curve3.toString());
                                    KGC kgc3 = new KGC(sm9Curve3);
                                    SM9 sm93 = new SM9(sm9Curve3);
                                    masterKey i1 = SM9Use.test_sm9_masterKeyEncap(kgc3, sm93);
                                    ibeDao.masterKeyUpdate(i1);
                                    break;
                                case 3:
                                    SM9Curve sm9Curve1 = new SM9Curve();
                                    Main.showMsg(sm9Curve1.toString());
                                    KGC kgc1 = new KGC(sm9Curve1);
                                    SM9 sm91 = new SM9(sm9Curve1);
                                    System.out.println("请输入需要密钥更新的用户: ");
                                    String id = s.next();
                                    String newKey = SM9Use.test_sm9_normalKeyEncap(kgc1, sm91, id);
                                    ibeDao.changePrivate(id, newKey);
                                    break;
                                case 4:
                                    System.out.println("请输入需要查询的用户: ");
                                    String pk = s.next();
                                    System.out.println(ibeDao.mangerSelect(pk));
                                    break;
                                case 5:
                                    System.out.println("请输入需要撤销的用户: ");
                                    String pk1 = s.next();
                                    ibeDao.deleteUser(pk1);
                                    System.out.println("撤销成功");
                                    break;
                                case 6:
                                    System.out.println("请输入需要修改的密码: ");
                                    String aPass2 = s.next();
                                    ibeDao.changePassword(admin, aPass2);
                                    System.out.println("修改成功！");
                                    break;
                                case 7:
                                    SM9Curve sm9Curve2 = new SM9Curve();
                                    Main.showMsg(sm9Curve2.toString());
                                    KGC kgc2 = new KGC(sm9Curve2);
                                    SM9 sm92 = new SM9(sm9Curve2);
                                    System.out.println("请输入注册信息: ");
                                    System.out.println("请输入用户身份: ");
                                    String identity = s.next();
                                    System.out.println("生成私钥为: ");
                                    String newKey2 = SM9Use.test_sm9_keyEncap(kgc2, sm92, identity);
                                    System.out.println("请输入密码: ");
                                    String pass = s.next();
                                    System.out.println("请输入用户等级: ");
                                    int level = s.nextInt();
                                    ibeTable newIbe = new ibeTable();
                                    newIbe.setPublicKey(identity);
                                    newIbe.setPrivateKey(newKey2);
                                    newIbe.setPassword(pass);
                                    newIbe.setLevel(level);
                                    ibeDao.signIn(newIbe);
                                    System.out.println("注册成功!");
                                    break;
                                case 8:
                                    System.out.println("成功退出!");
                                    break loopAll;
                            }
                        }
                    }

            case 2:
                System.out.println("请输入高级用户身份: ");
                String user1 = s.next();
                if (ibeDao.judgeLevel(user1) != 2) {
                    System.out.println("用户名错误或权限不足，系统退出");
                    break loopAll;
                }
                System.out.println("请输入高级用户密码: ");
                String uPass = s.next();
                if (ibeDao.Registered(user1)) {
                        while (!ibeDao.PasswordCheck(user1, uPass)) {
                            System.out.println("密码错误，请重新输入: ");
                            String uPass1 = s.next();
                            if (ibeDao.PasswordCheck(user1, uPass1)) {
                                break;
                            }
                        }
                        System.out.println("登录成功!");
                        while (true) {
                            System.out.println("------------高级用户功能界面------------");
                            System.out.println("--------------请输入选项--------------");
                            System.out.println("1: 用户自发更新密钥");
                            System.out.println("2: 用户信息查询");
                            System.out.println("3: 指定用户信息查询");
                            System.out.println("4: 用户密码修改");
                            System.out.println("5: 退出");
                            int choice3 = s.nextInt();
                            switch (choice3) {
                                case 1:
                                    SM9Curve sm9Curve = new SM9Curve();
                                    Main.showMsg(sm9Curve.toString());
                                    KGC kgc = new KGC(sm9Curve);
                                    SM9 sm9 = new SM9(sm9Curve);
                                    String newKey = SM9Use.test_sm9_keyEncap(kgc, sm9, user1);
                                    ibeDao.changePrivate(user1, newKey);
                                    System.out.println("当前时间为: " + System.currentTimeMillis());
                                    break;
                                case 2:
                                    System.out.println(ibeDao.mangerSelect(user1));
                                    break;
                                case 3:
                                    System.out.println("请输入要查询的用户身份: ");
                                    String id = s.next();
                                    System.out.println(ibeDao.normalSelect(id));
                                    break;
                                case 4:
                                    System.out.println("请输入需要修改的密码: ");
                                    String uPass3 = s.next();
                                    ibeDao.changePassword(user1, uPass3);
                                    System.out.println("修改成功！");
                                    break;
                                case 5:
                                    System.out.println("成功退出!");
                                    break loopAll;
                            }
                        }
                    }

            case 3:
                System.out.println("请输入普通用户身份: ");
                String user2 = s.next();
                if (ibeDao.judgeLevel(user2) != 3) {
                    System.out.println("用户名错误或权限不足，系统退出");
                    break loopAll;
                }
                System.out.println("请输入普通用户密码: ");
                String uPass2 = s.next();
                if (ibeDao.Registered(user2)) {
                        while (!ibeDao.PasswordCheck(user2, uPass2)) {
                            System.out.println("密码错误，请重新输入: ");
                            String uPass3 = s.next();
                            if (ibeDao.PasswordCheck(user2, uPass2)) {
                                break;
                            }
                        }
                        System.out.println("登录成功!");
                        while (true) {
                            System.out.println("------------普通用户功能界面------------");
                            System.out.println("--------------请输入选项--------------");
                            System.out.println("1: 查询用户信息");
                            System.out.println("2: 用户密码修改");
                            System.out.println("3: 退出");
                            int choice3 = s.nextInt();
                            switch (choice3) {
                                case 1:
                                    System.out.println(ibeDao.mangerSelect(user2));
                                    break;
                                case 2:
                                    System.out.println("请输入需要修改的密码: ");
                                    String uPass4 = s.next();
                                    ibeDao.changePassword(user2, uPass4);
                                    System.out.println("修改成功");
                                    break;
                                case 3:
                                    System.out.println("成功退出!");
                                    break loopAll;
                            }
                        }
                    }

            case 4:
                break loopAll;
        }
    }
}
