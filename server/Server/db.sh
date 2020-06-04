#!/bin/bash  

# Compile files
javac dbCreate.java
javac insertUsersDb.java

# Create db and tables
java -classpath ".:sqlite-jdbc-3.27.2.1.jar" dbCreate.java

# Insert users
java -classpath ".:sqlite-jdbc-3.27.2.1.jar" insertUsersDb.java
