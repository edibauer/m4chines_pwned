package org.strutted.htb;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class URLMapping {
    public boolean saveMapping(String shortId, String imagePath) {
        String insertSQL = "INSERT INTO URL_MAPPING (SHORT_ID, IMAGE_PATH) VALUES (?, ?);";
        try (Connection conn = DatabaseUtil.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {
            pstmt.setString(1, shortId);
            pstmt.setString(2, imagePath);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String getImagePath(String shortId) {
        String selectSQL = "SELECT IMAGE_PATH FROM URL_MAPPING WHERE SHORT_ID = ?;";
        try (Connection conn = DatabaseUtil.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(selectSQL)) {
            pstmt.setString(1, shortId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("IMAGE_PATH");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean shortIdExists(String shortId) {
        String selectSQL = "SELECT 1 FROM URL_MAPPING WHERE SHORT_ID = ?;";
        try (Connection conn = DatabaseUtil.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(selectSQL)) {
            pstmt.setString(1, shortId);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }
}