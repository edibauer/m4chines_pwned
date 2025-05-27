package org.strutted.htb;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.io.File;

public class DatabaseUtil {
    private static final String DB_URL = "jdbc:sqlite:" + System.getProperty("user.dir") + "/webapps/ROOT/db/url_mappings.db";

    static {
        try {
            Class.forName("org.sqlite.JDBC");
            initializeDatabase();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static void initializeDatabase() {
        String dbDirectoryPath = System.getProperty("user.dir") + "/webapps/ROOT/db/";
        File dbDirectory = new File(dbDirectoryPath);
        if (!dbDirectory.exists()) {
            if (dbDirectory.mkdirs()) {
                System.out.println("Database directory created.");
            } else {
                System.err.println("Failed to create database directory.");
            }
        }
        String createTableSQL = "CREATE TABLE IF NOT EXISTS URL_MAPPING ("
                + "SHORT_ID TEXT PRIMARY KEY,"
                + "IMAGE_PATH TEXT NOT NULL"
                + ");";

        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSQL);
            System.out.println("Database initialized successfully.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }
}