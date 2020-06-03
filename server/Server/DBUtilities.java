import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 *
 * @author sqlitetutorial.net
 */
public class DBUtilities {

    public DBUtilities() {
    }

    /**
     * Connect to the database.db database
     * 
     * @return the Connection object
     */
    public Connection connect() {
        // SQLite connection string
        String url = "jdbc:sqlite:c:/Carapaca/server/db/database.db";
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(url);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return conn;
    }

    // Create new Database
    public static void createNewDatabase(String fileName) {

        String url = "jdbc:sqlite:c:/Carapaca/server/db/" + fileName;

        try (Connection conn = DriverManager.getConnection(url)) {
            if (conn != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("The driver name is " + meta.getDriverName());
                System.out.println("A new database has been created.");
            }

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // create "user" Table
    public static void createUserTable() {
        String url = "jdbc:sqlite:c:/Carapaca/server/db/database.db";

        String sql = "CREATE TABLE IF NOT EXISTS users (\n" + " id integer PRIMARY KEY AUTOINCREMENT,\n"
                + " user text NOT NULL,\n" + " publickey text NOT NULL,\n" + " password text NOT NULL,\n"
                + " salt text NOT NULL\n" + ");";

        try (Connection conn = DriverManager.getConnection(url); Statement stmt = conn.createStatement()) {

            stmt.execute(sql);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // create "authenticated keys" Table
    public static void createAuthKey() {

        String url = "jdbc:sqlite:c:/Carapaca/server/db/database.db";

        String sql = "CREATE TABLE IF NOT EXISTS authenticatedkeys (\n" + " id integer PRIMARY KEY AUTOINCREMENT,\n"
                + " id_user integer NOT NULL,\n"
                + " ipaddr text NOT NULL,\n"
                + " publickey text NOT NULL,\n"
                + " FOREIGN KEY(id_user) REFERENCES users(id)" + ");";

        try (Connection conn = DriverManager.getConnection(url); Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // Drop table 'table'
    public static void dropTable(String table) {

        String url = "jdbc:sqlite:c:/Carapaca/server/db/database.db";

        String sql = "DROP TABLE "+table+";";

        try (Connection conn = DriverManager.getConnection(url); Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * Insert a new row into the user table
     *
     * @param user
     * @param pk
     * @param pw
     */
    public void insertUser(String user, String pk, byte[] pw) throws NoSuchAlgorithmException {
        String sql = "INSERT INTO users(user, publickey, password, salt) VALUES (?, ?, ?, ?)";
        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            String salt = "";
            String pwHex = "";
            salt = getSalt();
            pwHex = getHash(getHex(pw), salt);

            pstmt.setString(1, user);
            pstmt.setString(2, pk);
            pstmt.setString(3, pwHex);
            pstmt.setString(4, salt);
            pstmt.executeUpdate();
            System.out.println("CRIADO COM SUCESSO!");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * Insert a new row into the authenticatedkeys table
     *
     * @param id
     * @param pk
     */
    public void insertAuthKeys(int id, String ip, String pk) {
        String sql = "INSERT INTO authenticatedkeys(id_user, ipaddr, publickey) VALUES (?, ?, ?)";
        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.setString(2, ip);
            pstmt.setString(3, pk);
            pstmt.executeUpdate();
            System.out.println("CRIADO COM SUCESSO!");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // Select all from user
    public void selectAllUser() {
        String sql = "SELECT id, user, publickey, password, salt FROM users";

        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            // loop through the result set
            while (rs.next()) {
                System.out.println(rs.getInt("id") + "\t" + rs.getString("user") + "\t" + rs.getDouble("publickey")
                        + "\t" + rs.getString("password") + "\t" + rs.getString("salt"));
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // Select "id" from user
    public int selectIDUser(String user) {
        String sql = "SELECT id FROM users WHERE user = ?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, user);
            ResultSet rs = pstmt.executeQuery();
            int value = rs.getInt("id");
            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return 0;
        }
    }

    // Select "id" from user
    public int verifyUserExists(String user) {
        String sql = "SELECT COUNT(*) AS count FROM users WHERE user = ?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, user);
            ResultSet rs = pstmt.executeQuery();
            int value = rs.getInt("count");
            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return 0;
        }
    }

    // Select "public key" from user
    public String selectPKUser(int id) {
        String sql = "SELECT publickey FROM users WHERE id = ?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            ResultSet rs = pstmt.executeQuery();
            String value = rs.getString("publickey");
            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return "";
        }
    }

    // Select "password" from user
    public String selectPWUser(int id) {
        String sql = "SELECT password FROM users WHERE id = ?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            ResultSet rs = pstmt.executeQuery();
            String value = rs.getString("password");
            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return "exited";
        }
    }

    // Select "salt" from user
    public String selectSaltUser(int id) {
        String sql = "SELECT salt FROM users WHERE id = ?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            ResultSet rs = pstmt.executeQuery();
            String value = rs.getString("salt");
            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return "";
        }
    }

    // Select "public key" from authenticatedkeys
    public String selectPKAuthKeys(int id) throws SQLException {
        String sql = "SELECT publickey FROM authenticatedkeys WHERE id_user=?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, id);
            ResultSet rs = pstmt.executeQuery();
            String value = rs.getString("publickey");

            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return "";
        }
    }

    // Verify "public key" from authenticatedkeys
    public int verifyPKAuthKeys(String pk, int id) throws SQLException {
        String sql = "SELECT COUNT(*) AS count FROM authenticatedkeys WHERE publickey = ? AND id_user = ?";

        try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, pk);
            pstmt.setInt(2, id);
            ResultSet rs = pstmt.executeQuery();
            int value = rs.getInt("count");
            return value;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return 0;
        }
    }

    // Return a hash value
    public static String getHash(String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");

        String topSecret = salt + password + salt;

        byte[] bytes = md.digest(topSecret.getBytes());

        return getHex(bytes);
    }

    // Generate a salt
    public static String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return getHex(salt);
    }

    // Convert to Hex
    public static String getHex(byte[] raw) throws NoSuchAlgorithmException {
        String sReturn = "";
        for (final byte b : raw) {
            int iPrimeiroHex = (b >> 4) & 0x0f;
            switch (iPrimeiroHex) {
                case 0:
                    sReturn = sReturn + "0";
                    break;
                case 1:
                    sReturn = sReturn + "1";
                    break;
                case 2:
                    sReturn = sReturn + "2";
                    break;
                case 3:
                    sReturn = sReturn + "3";
                    break;
                case 4:
                    sReturn = sReturn + "4";
                    break;
                case 5:
                    sReturn = sReturn + "5";
                    break;
                case 6:
                    sReturn = sReturn + "6";
                    break;
                case 7:
                    sReturn = sReturn + "7";
                    break;
                case 8:
                    sReturn = sReturn + "8";
                    break;
                case 9:
                    sReturn = sReturn + "9";
                    break;
                case 10:
                    sReturn = sReturn + "a";
                    break;
                case 11:
                    sReturn = sReturn + "b";
                    break;
                case 12:
                    sReturn = sReturn + "c";
                    break;
                case 13:
                    sReturn = sReturn + "d";
                    break;
                case 14:
                    sReturn = sReturn + "e";
                    break;
                case 15:
                    sReturn = sReturn + "f";
                    break;
            }

            int iSegundoHex = b & 0x0f;
            switch (iSegundoHex) {
                case 0:
                    sReturn = sReturn + "0";
                    break;
                case 1:
                    sReturn = sReturn + "1";
                    break;
                case 2:
                    sReturn = sReturn + "2";
                    break;
                case 3:
                    sReturn = sReturn + "3";
                    break;
                case 4:
                    sReturn = sReturn + "4";
                    break;
                case 5:
                    sReturn = sReturn + "5";
                    break;
                case 6:
                    sReturn = sReturn + "6";
                    break;
                case 7:
                    sReturn = sReturn + "7";
                    break;
                case 8:
                    sReturn = sReturn + "8";
                    break;
                case 9:
                    sReturn = sReturn + "9";
                    break;
                case 10:
                    sReturn = sReturn + "a";
                    break;
                case 11:
                    sReturn = sReturn + "b";
                    break;
                case 12:
                    sReturn = sReturn + "c";
                    break;
                case 13:
                    sReturn = sReturn + "d";
                    break;
                case 14:
                    sReturn = sReturn + "e";
                    break;
                case 15:
                    sReturn = sReturn + "f";
                    break;
            }
        }

        return sReturn;
    }
}