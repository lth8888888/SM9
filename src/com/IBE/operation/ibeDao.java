package com.IBE.operation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ibeDao {
    //生成主公私钥对
    public static void masterKey(masterKey i) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "insert into masterkey(Id, masterPublicKey, masterPrivateKey) values(?, ?, ?)";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setInt(1, 1);
        p.setString(2, i.getMasterPublicKey());
        p.setString(3, i.getMasterPrivateKey());
        p.execute();
    }

    //更新主公私钥对
    public static void masterKeyUpdate(masterKey i) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "update masterkey set masterPublicKey=?, masterPrivateKey=? where Id=1";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, i.getMasterPublicKey());
        p.setString(2, i.getMasterPrivateKey());
        p.execute();
    }

    //非监管用户更新密钥时更新自己的主公私钥对
    public static void masterUserKeyUpdate(String pk, masterKey i) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "update masterkey set masterPublicKey=?, masterPrivateKey=? where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, i.getMasterPublicKey());
        p.setString(2, i.getMasterPrivateKey());
        p.setString(3, pk);
        p.execute();
    }

    //注册
    public static void signIn(ibeTable i) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "insert into ibe(IdInformation, PrivateKey, Password, UserLevel) values(?, ?, ?, ?)";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, i.getPublicKey());
        p.setString(2, i.getPrivateKey());
        p.setString(3, i.getPassword());
        p.setInt(4, i.getLevel());
        p.execute();
    }

    //判断注册状态
    public static boolean Registered(String pk) throws SQLException {
        boolean state = false;
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select * from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        if (rs.next())
            state = true;
        return state;
    }

    //判断用户等级
    public static int judgeLevel(String pk) throws SQLException {
        boolean state = false;
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select * from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        int level = 0;
        if (rs.next())
            level = rs.getInt("UserLevel");
        return level;
    }

    //判断密码是否正确
    public static boolean PasswordCheck(String pk, String password) throws SQLException {
        boolean state = false;
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select Password from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        if (rs.next()) {
            if (rs.getString("Password").equals(password)) {
                state = true;
            }
        }
        return state;
    }

    //管理员查询指定用户或用户自身查询
    public static ibeTable mangerSelect(String pk) throws SQLException {
        ibeTable i = null;
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select * from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        if (rs.next()) {
            ibeTable b = new ibeTable();
            b.setPublicKey(pk);
            b.setPrivateKey(rs.getString("PrivateKey"));
            b.setPassword(rs.getString("Password"));
            b.setLevel(rs.getInt("UserLevel"));
            i = b;
        }
        return i;
    }

    //高级用户查询其他用户
    public static ibeTable normalSelect(String pk) throws SQLException {
        ibeTable i = null;
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select * from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        if (rs.next()) {
            ibeTable b = new ibeTable();
            b.setPublicKey(pk);
            b.setLevel(rs.getInt("UserLevel"));
            i = b;
        }
        return i;
    }

    //密钥更新
    public static void changePrivate(String pk, String PrK) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select * from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        String sqlUpdate = "update ibe set PrivateKey=? where IdInformation=?";
        PreparedStatement p1 = conn.prepareStatement(sqlUpdate);
        p1.setString(1, PrK);
        p1.setString(2, pk);
        p1.execute();
        System.out.println("密钥更新成功");
    }

    //身份撤销
    public static void deleteUser(String pk) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "delete from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        p.execute();
    }

    //修改可变Id
    public static void change_vId(String pk, String vId) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "select * from ibe where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, pk);
        ResultSet rs = p.executeQuery();
        String sqlUpdate = "update ibe set vId=? where IdInformation=?";
        PreparedStatement p1 = conn.prepareStatement(sqlUpdate);
        p1.setString(1, vId);
        p1.setString(2, pk);
        p1.execute();
    }

    //修改密码
    public static void changePassword(String pk, String password) throws SQLException {
        Connection conn = JdbcUtiils.getConnection();
        String sql = "update ibe set Password=? where IdInformation=?";
        PreparedStatement p = conn.prepareStatement(sql);
        p.setString(1, password);
        p.setString(2, pk);
        p.execute();
    }

}
