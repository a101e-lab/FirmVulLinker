import mysql.connector
from mysql.connector import Error

class Database:
    def __init__(self, host_name, user_name, user_password, db_name=None, port=3307):
        self.host_name = host_name
        self.user_name = user_name
        self.user_password = user_password
        self.db_name = db_name
        self.port = port
        self.connection = self.create_connection()

    def create_connection(self):
        connection = None
        try:
            if self.db_name:
                connection = mysql.connector.connect(
                    host=self.host_name,
                    user=self.user_name,
                    passwd=self.user_password,
                    database=self.db_name,
                    port=self.port
                )
            else:
                connection = mysql.connector.connect(
                    host=self.host_name,
                    user=self.user_name,
                    passwd=self.user_password,
                    port=self.port
                )
            print("MySQL Database connection successful")
        except Error as e:
            print(f"The error '{e}' occurred")
        return connection

    def create_database(self):
        connection = mysql.connector.connect(
            host=self.host_name,
            user=self.user_name,
            passwd=self.user_password,
            port=self.port
        )
        cursor = connection.cursor()
        try:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.db_name}")
            print(f"Database '{self.db_name}' created successfully")
        except Error as e:
            print(f"The error '{e}' occurred")
        connection.close()

    def execute_query(self, query):
        cursor = self.connection.cursor()
        try:
            cursor.execute(query)
            self.connection.commit()
            print("Query executed successfully")
        except Error as e:
            print(f"The error '{e}' occurred")

    def execute_read_query(self, query):
        cursor = self.connection.cursor()
        result = None
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            return result
        except Error as e:
            print(f"The error '{e}' occurred")

# Example usage:
if __name__ == "__main__":
    db = Database("localhost", "root", "StrongPassw0rd!","firmware_info")
    db.create_database()
    create_firmware_info_table_query = """
    CREATE TABLE IF NOT EXISTS firmware_info (
        id INT AUTO_INCREMENT PRIMARY KEY,
        firmware_hash VARCHAR(64) NOT NULL,
        firmware_name VARCHAR(255) NOT NULL,
        architecture VARCHAR(50),
        filesystem VARCHAR(50),
        operating_system VARCHAR(50),
        UNIQUE(firmware_hash, firmware_name)
    );
    """
    create_fuzzy_hashes_table_query = """
        CREATE TABLE IF NOT EXISTS fuzzy_hashes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            firmware_id INT NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            file_hash VARCHAR(255) NOT NULL,
            ssdeep_hash TEXT NOT NULL,
            sdhash_hash TEXT NOT NULL,
            FOREIGN KEY (firmware_id) REFERENCES firmware_info(id),
            UNIQUE (firmware_id, file_hash)
        );
        """
    db.execute_query(create_firmware_info_table_query)
    db.execute_query(create_fuzzy_hashes_table_query)

