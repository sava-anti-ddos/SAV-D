import sqlite3
from queue import Queue
from threading import Lock
from datetime import datetime
import csv
import os
import shutil
import glob
from config import Config
from log import get_logger

logger = get_logger(__name__)


class Database:
    """
    A singleton class representing a database for managing IP SnifferInfos.

    Attributes:
        db_name (str): The name of the database file.
        pool (Queue): A queue of database connections.
        lock (Lock): A lock for thread-safe access to the connection pool.

    Methods:
        create_connection: Creates a new database connection.
        get_connection: Retrieves a connection from the connection pool.
        release_connection: Releases a connection back to the connection pool.
        create_table: Creates the SnifferInfo table if it doesn't exist.
        SnifferInfo_update: Updates or inserts a new entry in the SnifferInfo table.
        SnifferInfo_update_batch: Updates or inserts multiple entries in the SnifferInfo table.
        duration_update: Updates the duration of each entry in the SnifferInfo table.
        timeout_remove: Removes entries from the SnifferInfo table based on a duration threshold.
        display: Displays all entries in the SnifferInfo table.
        delete: Deletes an entry from the SnifferInfo table.
        id_reset: Resets the primary key of the SnifferInfo table.
        clear: Clears all data from the database.
        close: Closes all database connections.

    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Create a new instance of the class if it doesn't already exist.

        Args:
            cls: The class object.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            The instance of the class.

        """
        if not cls._instance:
            cls._instance = super(Database, cls).__new__(cls)
        return cls._instance

    def __init__(self, dbname, max_connections=5):
        """
            Initializes the SnifferInfo object.

            Args:
                dbname (str): The name of the database file.
                max_connections (int, optional): The maximum number of connections to the database. Defaults to 5.
            """
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self.db_name = dbname
            if not os.path.isfile(self.db_name):
                self.create_table()
            self.pool = Queue(max_connections)
            self.lock = Lock()
            for _ in range(max_connections):
                self.pool.put(self.create_connection())
            logger.info("SnifferInfo init")

    def create_connection(self):
        """
            Creates a connection to the SQLite database.

            Returns:
                sqlite3.Connection: The connection object.
            """
        logger.info("Create connection to SQLite database")
        return sqlite3.connect(self.db_name, check_same_thread=False)

    def get_connection(self):
        """
            Retrieves a connection from the connection pool.

            Returns:
                Connection: A connection object from the pool.
            """
        logger.info("Get connection from pool")
        return self.pool.get()

    def release_connection(self, conn):
        """
        Releases a connection back to the connection pool.

        Args:
            conn: The connection to be released.

        Returns:
            None
        """
        logger.info("Release connection to pool")
        self.pool.put(conn)

    def create_table(self):
        """
        Creates a table named 'SnifferInfo' in the SQLite database if it doesn't already exist.

        The table has the following columns:
        - id: INTEGER PRIMARY KEY 
        - sip: TEXT
        - dip: TEXT
        - sport: INTEGER
        - dport: INTEGER
        - protocol: TEXT
        - tcp_flag: TEXT
        - timestamp: TEXT
        - length: TEXT
        - time_arr: TEXT
        - duration: TEXT
        - count: INTEGER (Default value: 1)
        """
        logger.info("Create table SnifferInfo")
        conn = sqlite3.connect(self.db_name)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SnifferInfo (
                    id INTEGER PRIMARY KEY,
                    sip TEXT,
                    dip TEXT,
                    sport INTEGER,
                    dport INTEGER,
                    protocol TEXT,
                    tcp_flag TEXT,
                    timestamp TEXT,
                    length TEXT,
                    time_arr TEXT,
                    duration TEXT,
                    count INTEGER DEFAULT 1
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS IPBlacklist (
                    id INTEGER PRIMARY KEY,
                    ip TEXT,
                    time_arr TEXT,
                    duration TEXT
                )
            ''')
            conn.commit()
        except sqlite3.OperationalError as e:
            logger.error(f"An error occurred while creating the table: {e}")
        finally:
            conn.close()

    def sniffer_info_update(self, sip, dip, sport, dport, protocol, tcp_flag,
                            timestamp, length):
        """
            Update or insert a record in the SnifferInfo table based on the given parameters.

            Args:
                sip (str): Source IP address.
                dip (str): Destination IP address.
                sport (int): Source port number.
                dport (int): Destination port number.
                protocol (str): Protocol used.
                tcp_flag (int): TCP flag value.
                timestamp (str): Timestamp of the packet.
                length (int): Length of the packet.

            Returns:
                None
            """
        logger.info("Update or insert a record in the SnifferInfo table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                    SELECT id, count FROM SnifferInfo
                    WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
                ''', (sip, dip, sport, dport, protocol))
            result = cursor.fetchone()
            if result:
                packet_id, count = result
                cursor.execute(
                    '''
                        UPDATE SnifferInfo SET count = ?, tcp_flag = ?, timestamp=? ,length = ? , time_arr = ? WHERE id = ?
                    ''',
                    (count + 1, tcp_flag, timestamp, length,
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"), packet_id))
            else:
                cursor.execute(
                    '''
                        INSERT INTO SnifferInfo (sip, dip, sport, dport, protocol, tcp_flag, timestamp,length,time_arr)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (sip, dip, sport, dport, protocol, tcp_flag, timestamp,
                          length, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)

    def sniffer_info_update_batch(self, data):
        """
            Update the SnifferInfo with a batch of data.

            Args:
                data (list): A list of dictionaries containing the data to be updated.
                    Each dictionary should have the following keys: 'sip', 'dip', 'sport',
                    'dport', 'protocol', 'tcp_flag', 'timestamp', 'length'.

            Returns:
                None
            """
        logger.info("Update the SnifferInfo with a batch of data")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for row in data:
                sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = (
                    row['sip'], row['dip'], row['sport'], row['dport'],
                    row['protocol'], row['tcp_flag'], row['timestamp'],
                    row['length'])
                cursor.execute(
                    '''
                        SELECT id, count FROM SnifferInfo
                        WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
                    ''', (sip, dip, sport, dport, protocol))
                result = cursor.fetchone()
                if result:
                    packet_id, count = result
                    cursor.execute(
                        '''
                            UPDATE SnifferInfo SET count = ?, tcp_flag = ?, timestamp = ?, length = ?, time_arr = ? WHERE id = ?
                        ''', (
                            count + 1,
                            tcp_flag,
                            timestamp,
                            length,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            packet_id,
                        ))
                else:
                    cursor.execute(
                        '''
                            INSERT INTO SnifferInfo (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (sip, dip, sport, dport, protocol, tcp_flag, timestamp,
                         length, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)

    def ip_blacklist_update(self, ip):
        """
        Update or insert a record in the IPBlacklist table based on the given parameters.

        Args:
            ip (str): IP address.
            duration (str): duration information of the IP address.

        Returns:
            None
        """
        logger.info("Update or insert a record in the IPBlacklist table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Check if the IP already exists
            cursor.execute(
                '''
                    SELECT ip FROM IPBlacklist WHERE ip = ?
                ''', (ip,))
            result = cursor.fetchone()
            if result:
                # Update time_arr if IP exists
                cursor.execute(
                    '''
                        UPDATE IPBlacklist SET  time_arr = ? WHERE ip = ?
                    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip))
            else:
                # Insert new record if IP does not exist
                cursor.execute(
                    '''
                        INSERT INTO IPBlacklist (ip, time_arr,duration) VALUES (?, ?, ?)
                    ''', (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0))
            conn.commit()
        except Exception as e:
            logger.error(
                f"An error occurred while updating the IPBlacklist table: {e}")
        finally:
            self.release_connection(conn)

    def ip_blacklist_update_batch(self, data):
        """
        Update the IPBlacklist table with a batch of data.

        Args:
            data (list): A list of dictionaries containing the data to be updated.
                Each dictionary should have the following keys: 'ip', 'duration'.

        Returns:
            None
        """
        logger.info("Update the IPBlacklist table with a batch of data")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for row in data:
                ip = row['ip']  # Assuming each row is a dictionary
                cursor.execute(
                    '''
                        SELECT ip FROM IPBlacklist WHERE ip = ?
                    ''', (ip,))
                result = cursor.fetchone()
                if result:
                    cursor.execute(
                        '''
                            UPDATE IPBlacklist SET time_arr = ? WHERE ip = ?
                        ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip))
                else:
                    cursor.execute(
                        '''
                            INSERT INTO IPBlacklist (ip, time_arr) VALUES (?, ?)
                        ''', (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        except Exception as e:
            logger.error(
                f"An error occurred while batch updating the IPBlacklist table: {e}"
            )
        finally:
            self.release_connection(conn)

    def duration_update(self, table_name):
        """
            Updates the duration of each packet in the SnifferInfo table based on the current time.

            This method retrieves the list of packets from the SnifferInfo table and calculates the duration
            for each packet by subtracting the arrival time from the current time. It then updates the
            duration field in the SnifferInfo table for each packet.

            Returns:
                None
            """
        logger.info("Update the duration of each packet in the %s table" %
                    table_name)
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            now = datetime.now()
            # cursor.execute('SELECT id, time_arr FROM SnifferInfo')
            cursor.execute(f'PRAGMA table_info({table_name})')
            cursor.execute(f'SELECT id,time_arr FROM {table_name}')
            rows = cursor.fetchall()
            for row in rows:
                packet_id, arrival_time = row
                arrival_datetime = datetime.strptime(arrival_time,
                                                     "%Y-%m-%d %H:%M:%S")
                duration_in_seconds = (now - arrival_datetime).total_seconds()
                cursor.execute(
                    f'UPDATE {table_name} SET duration = ? WHERE id = ?',
                    (duration_in_seconds, packet_id))
            conn.commit()
        finally:
            self.release_connection(conn)

    def timeout_remove(self, table_name, duration_threshold):
        """
        Delete entries in the SnifferInfo with a duration greater than the specified threshold.

        Args:
            duration_threshold (int): The threshold duration in seconds.

        Returns:
            None
        """
        logger.info(
            "Delete entries in the %s table with a duration greater than %d." %
            (table_name, duration_threshold))

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f'DELETE FROM {table_name} WHERE CAST(duration AS INTEGER) > ?',
                (duration_threshold,))
            conn.commit()
        finally:
            self.release_connection(conn)

    def display(self, table_name):
        """
        Display all records from the specified table.

        Retrieves all rows from the specified table and prints them in a formatted manner.
        The format includes columns dynamically fetched from the table schema.

        Args:
            table_name (str): The name of the table to display records from.
        """
        logger.info(f"Display all records from the {table_name}")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(f'PRAGMA table_info({table_name})')
            columns_info = cursor.fetchall()
            column_names = [col[1] for col in columns_info
                           ]  # Extract column names

            cursor.execute(f'SELECT * FROM {table_name}')
            rows = cursor.fetchall()

            # Create a format string dynamically based on the number of columns
            format_str = ' '.join(["{:<15}"] * len(column_names))
            print(format_str.format(*column_names))

            for row in rows:
                formatted_row = [
                    str(v) if v is not None else 'None' for v in row
                ]
                print(format_str.format(*formatted_row))
        finally:
            self.release_connection(conn)

    def delete(self, table_name, id):
        """
        Delete a record from the specified table based on the given ID.

        Args:
            table_name (str): The name of the table from which to delete the record.
            id (int): The ID of the record to be deleted.

        Returns:
            None

        Raises:
            Exception: If an error occurs during the deletion process.
        """
        logger.info(f"Deleting a record from the {table_name} table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f'''
                DELETE FROM {table_name} WHERE id = ?
                ''', (id,))
            conn.commit(
            )  # Make sure to commit the transaction to apply the changes
            print("Record deleted successfully!")
        except Exception as e:
            logger.error(
                f"An error occurred while deleting a record from the {table_name} table: {e}"
            )
            raise e
        finally:
            self.release_connection(conn)

    def id_reset(self, table_name):
        """
        Resets the IDs in the specified table to ensure continuity. This is particularly useful after deletion
        operations which may leave gaps in the ID sequence. The function handles tables differently based on
        their structure: it directly resets IDs for tables with an auto-increment ID column, and it reassigns
        IDs in a continuous sequence for tables without such a column.

        Args:
            table_name (str): The name of the table for which to reset IDs.

        Returns:
            None
        """
        logger.info(f"Starting ID reset for the {table_name} table.")

        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            if table_name == 'SnifferInfo':
                # Handle SnifferInfo table - Assumes it has an auto-increment ID column
                cursor.execute(f'''
                    CREATE TABLE IF NOT EXISTS {table_name}_temp (
                        id INTEGER PRIMARY KEY,
                        sip TEXT,
                        dip TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        protocol TEXT,
                        tcp_flag TEXT,
                        timestamp TEXT,
                        length TEXT,
                        time_arr TEXT,
                        duration TEXT,
                        count INTEGER DEFAULT 1
                    )
                ''')
                cursor.execute(f'''
                    INSERT INTO {table_name}_temp (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr, duration, count)
                    SELECT sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr, duration, count FROM {table_name}
                ''')
            elif table_name == 'IPBlacklist':
                cursor.execute(f'''
                    CREATE TABLE IF NOT EXISTS {table_name}_temp (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        time_arr TEXT,
                        duration TEXT
                    );
                ''')
                # 直接复制数据，id 将自动处理
                cursor.execute(f'''
                    INSERT INTO {table_name}_temp (ip, time_arr, duration)
                    SELECT ip, time_arr, duration FROM {table_name};
                ''')
            else:
                logger.error(
                    f"Table {table_name} is not recognized for ID reset.")
                return

            # Drop the original table and rename the temporary table
            cursor.execute(f'DROP TABLE {table_name};')
            cursor.execute(
                f'ALTER TABLE {table_name}_temp RENAME TO {table_name};')
            conn.commit()
            logger.info(f"ID reset completed for the {table_name} table.")
        except Exception as e:
            logger.error(
                f"An error occurred during ID reset for {table_name}: {e}")
        finally:
            self.release_connection(conn)

    def clear(self, table_name):
        """
            Clears all data from the tables in the database.

            Raises:
                sqlite3.Error: If an error occurs while clearing the tables.
            """
        logger.info(
            f"Clear all data from the {table_name}tables in the database")
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            for table_name in tables:
                logger.info(f"Clearing data from table: {table_name[0]}")
                cursor.execute(f"DELETE FROM {table_name[0]}")
            conn.commit()
            logger.info("All data has been cleared from the database")
        except sqlite3.Error as e:
            logger.error(f"An error occurred: {e}")
        finally:
            self.release_connection(conn)

    def close(self):
        """
            Closes all connections in the pool.

            This method iterates over the connection pool and closes each connection.
            """
        logger.info("Close all connections in the pool")
        while not self.pool.empty():
            conn = self.pool.get()
            conn.close()


class CSVHandler:
    """
    A class that handles reading CSV files, processing the data, and moving the files to a target directory.

    Args:
        readpath (str): The directory path where the CSV files are located.
        writepath (str): The directory path where the processed CSV files will be moved.
        encodetype (str): The encoding type of the CSV files.

    Attributes:
        csv_dir (str): The directory path where the CSV files are located.
        target_dir (str): The directory path where the processed CSV files will be moved.
        encoding (str): The encoding type of the CSV files.
    """

    def __init__(self, readpath, writepath, encodetype):
        self.csv_dir = readpath
        self.target_dir = writepath
        self.encoding = encodetype

        if not os.path.exists(readpath):
            logger.info(f"The directory does not exist: " + readpath)
            os.makedirs(readpath)

        if not os.path.exists(writepath):
            logger.info(f"The directory does not exist: " + writepath)
            os.makedirs(writepath)

    def csv_read_and_move(self):
        """
        Reads the CSV files from the specified directory, processes the data, and moves the files to the target directory.

        Returns:
            list: A list of dictionaries containing the processed data from the CSV files.
        """
        logger.info(
            "Read the CSV files from the specified directory, process the data, and move the files to the target directory"
        )
        csv_files = glob.glob(os.path.join(self.csv_dir, '*.csv'))
        data = []
        for file_path in csv_files:
            try:
                with open(file_path, mode='r', encoding=self.encoding) as file:
                    reader = csv.reader(file)
                    for row in reader:
                        parts = row[0].split(',')
                        sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = parts
                        sport = int(sport)
                        dport = int(dport)
                        record = {
                            'sip':
                                sip,
                            'dip':
                                dip,
                            'sport':
                                sport,
                            'dport':
                                dport,
                            'protocol':
                                protocol,
                            'tcp_flag':
                                tcp_flag if tcp_flag != 'None' else None,
                            'timestamp':
                                timestamp,
                            'length':
                                length
                        }
                        data.append(record)
                logger.info(f"Successfully read the CSV file: {file_path}")
            except Exception as e:
                logger.error(f"Failed to read the CSV file, error message: {e}")

            shutil.move(
                file_path,
                os.path.join(self.target_dir, os.path.basename(file_path)))

            logger.info(
                f"File has been moved to: {os.path.join(self.target_dir, os.path.basename(file_path))}"
            )

        return data


if __name__ == "__main__":
    'Create a Database instance'
    # db = Database("database.db")
    'Create the SnifferInfo table if it doesnt exist'
    # db.create_table()
    # print("display Sniffer table")
    # db.display("SnifferInfo")
    # print("display IPBlacklist table")
    # db.display("IPblacklist")
    'Read the CSV files, process the data, and move the files to the target directory'
    # csv_handler = CSVHandler(Config.readinfo_path,Config.writeinfo_path,Config.encoding)
    # processed_data = csv_handler.csv_read_and_move()
    'Update or insert a record in the SnifferInfo table'
    # print("display SnifferInfo_update")
    # db.SnifferInfo_update("192.1.0.1", "192.18.0.2", 1234, 5678, "TCP", 1, "2022-01-01 00:00:00", 100)
    # db.display("SnifferInfo")
    'Update the SnifferInfo table with a batch of data'
    # print("display SnifferInfo_update_batch")
    # db.SnifferInfo_update_batch(processed_data)
    # db.display("SnifferInfo")
    'Update or insert a record in the IPBlacklist table'
    # db.IPBlacklist_update("192.16.0.1")
    # print("display ipblacklist_update")
    # db.display("IPBlacklist")
    'Update the IPBlacklist table with a batch of data'
    # blacklist_data = [
    #     {"ip": "199.1.0.2"},
    #     {"ip": "190.2.0.3"},
    #     {"ip": "192.1.0.2"},
    # ]
    # print("display ipblacklist_update_batch")
    # print("before")
    # db.display("IPBlacklist")
    # db.IPBlacklist_update_batch(blacklist_data)
    # print("after")
    # db.display("IPBlacklist")
    'Update the duration of each packet in the SnifferInfo table'
    # print("update snifferinfo duration")
    # print("before")
    # db.display("SnifferInfo")
    # db.duration_update("SnifferInfo")
    # print("after")
    # db.display("SnifferInfo")
    'Delete entries in the SnifferInfo table with a duration greater than x seconds'
    # print("remove snifferinfo timeout")
    # print("before")
    # db.display("SnifferInfo")
    # db.timeout_remove("SnifferInfo", 10)
    # print("after")
    # db.display("SnifferInfo")
    'Update the duration of each packet in the IPBlacklist table'
    # print("update IPBlacklist duration")
    # print("before")
    # db.display("IPBlacklist")
    # db.duration_update("IPBlacklist")
    # print("after")
    # db.display("IPBlacklist")
    'Delete entries in the SnifferInfo table with a duration greater than 20 seconds'
    # print("remove IPBlacklist timeout")
    # print("before")
    # db.display("IPBlacklist")
    # db.timeout_remove("IPBlacklist", 20)
    # print("after")
    # db.display("IPBlacklist")
    'resort snifferinfo id'
    # print("reset SnifferInfo id")
    # print("before")
    # db.display("SnifferInfo")
    # db.id_reset("SnifferInfo")
    # print("after")
    # db.display("SnifferInfo")
    'resort ipblacklist id'
    # print("reset IPBlacklist id")
    # print("before")
    # db.display("IPBlacklist")
    # db.id_reset("IPBlacklist")
    # print("after")
    # db.display("IPBlacklist")
    'clear table snifferinfo'
    # print("clear SnifferInfo")
    # print("before")
    # db.display("SnifferInfo")
    # db.clear("SnifferInfo")
    # print("after")
    # db.display("SnifferInfo")
    'clear table ipblacklist'
    # print("clear IPBlacklist")
    # print("before")
    # db.display("IPBlacklist")
    # db.clear("IPBlacklist")
    # print("after")
    # db.display("IPBlacklist")
    'Close all connections in the pool'
    # db.close()
