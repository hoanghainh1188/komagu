package com.example.ams;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.stream.Collectors;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/** JDBC helper. Production pointed at ams-db01.rehearsal.invalid before this app was containerised. */
public class Db implements ServletContextListener {
    static final String URL = "jdbc:h2:mem:ams;DB_CLOSE_DELAY=-1";

    public static Connection open() throws SQLException {
        try {
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException(e);
        }
        return DriverManager.getConnection(URL, "sa", "");
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        try (InputStream in = Db.class.getResourceAsStream("/seed.sql");
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
             Connection conn = open();
             Statement st = conn.createStatement()) {
            for (String sql : reader.lines().collect(Collectors.joining("\n")).split(";")) {
                if (!sql.trim().isEmpty()) {
                    st.execute(sql);
                }
            }
        } catch (IOException | SQLException e) {
            throw new IllegalStateException("seed failed", e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        // The in-memory database goes away with the JVM.
    }
}
