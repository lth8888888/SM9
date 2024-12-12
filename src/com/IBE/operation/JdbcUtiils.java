package com.IBE.operation;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class JdbcUtiils {
    private static String Driver = "com.mysql.jdbc.Driver";
    private static String username = "root";
    private static String password = "123456";
    private static String url = "jdbc:mysql://127.0.0.1:3306/test?characterEncoding=UTF-8";
    private static Connection c = null;

    static {
        try {
            Class.forName(Driver);
            c = DriverManager.getConnection(url, username, password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (c != null)
            System.out.println("数据库连接成功");
    }

    public static Connection getConnection() {
        return c;
    }
}
