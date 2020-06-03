
public class dbCreate {

    public static void main(String[] args) {
        
        // Create Database
        DBUtilities.createNewDatabase("database.db");

        // Drop table auth_keys
        DBUtilities.dropTable("users");

        // Create Users Table
        DBUtilities.createUserTable();

        // Drop table auth_keys
        DBUtilities.dropTable("authenticatedkeys");

        // Create Auth_Keys Table
        DBUtilities.createAuthKey();
    }
    
}