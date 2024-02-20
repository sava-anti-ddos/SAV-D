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


class BlacklistDatabase:
    """
    A singleton class representing a database for managing IP blacklists.

    Attributes:
        db_name (str): The name of the database file.
        pool (Queue): A queue of database connections.
        lock (Lock): A lock for thread-safe access to the connection pool.

    Methods:
        create_connection: Creates a new database connection.
        get_connection: Retrieves a connection from the connection pool.
        release_connection: Releases a connection back to the connection pool.
        create_table: Creates the Blacklist table if it doesn't exist.
        blacklist_update: Updates or inserts a new entry in the Blacklist table.
        blacklist_update_batch: Updates or inserts multiple entries in the Blacklist table.
        duration_update: Updates the duration of each entry in the Blacklist table.
        timeout_remove: Removes entries from the Blacklist table based on a duration threshold.
        display: Displays all entries in the Blacklist table.
        delete: Deletes an entry from the Blacklist table.
        id_reset: Resets the primary key of the Blacklist table.
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
            cls._instance = super(BlacklistDatabase, cls).__new__(cls)
        return cls._instance

    def __init__(self, dbname, max_connections=5):
        """
            Initializes the IPBlacklist object.

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
            logger.info("Blacklist init")

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
        Creates a table named 'Blacklist' in the SQLite database if it doesn't already exist.

        The table has the following columns:
        - id: INTEGER (Primary Key)
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
        logger.info("Create table Blacklist")
        conn = sqlite3.connect(self.db_name)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Blacklist (
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
            conn.commit()
        except sqlite3.OperationalError as e:
            logger.error(f"An error occurred while creating the table: {e}")
        finally:
            conn.close()

    def blacklist_update(self, sip, dip, sport, dport, protocol, tcp_flag,
                         timestamp, length):
        """
            Update or insert a record in the Blacklist table based on the given parameters.

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
        logger.info("Update or insert a record in the Blacklist table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                    SELECT id, count FROM Blacklist
                    WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
                ''', (sip, dip, sport, dport, protocol))
            result = cursor.fetchone()
            if result:
                packet_id, count = result
                cursor.execute(
                    '''
                        UPDATE Blacklist SET count = ?, tcp_flag = ?, timestamp=? ,length = ? , time_arr = ? WHERE id = ?
                    ''',
                    (count + 1, tcp_flag, timestamp, length,
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"), packet_id))
            else:
                cursor.execute(
                    '''
                        INSERT INTO Blacklist (sip, dip, sport, dport, protocol, tcp_flag, timestamp,length,time_arr)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)
                    ''', (sip, dip, sport, dport, protocol, tcp_flag, timestamp,
                          length, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)

    def blacklist_update_batch(self, data):
        """
            Update the blacklist with a batch of data.

            Args:
                data (list): A list of dictionaries containing the data to be updated.
                    Each dictionary should have the following keys: 'sip', 'dip', 'sport',
                    'dport', 'protocol', 'tcp_flag', 'timestamp', 'length'.

            Returns:
                None
            """
        logger.info("Update the blacklist with a batch of data")
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
                        SELECT id, count FROM Blacklist
                        WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
                    ''', (sip, dip, sport, dport, protocol))
                result = cursor.fetchone()
                if result:
                    packet_id, count = result
                    cursor.execute(
                        '''
                            UPDATE Blacklist SET count = ?, tcp_flag = ?, timestamp = ?, length = ?, time_arr = ? WHERE id = ?
                        ''', (count + 1, tcp_flag, timestamp, length,
                              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                              packet_id))
                else:
                    cursor.execute(
                        '''
                            INSERT INTO Blacklist (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (sip, dip, sport, dport, protocol, tcp_flag, timestamp,
                         length, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)

    def duration_update(self):
        """
            Updates the duration of each packet in the Blacklist table based on the current time.

            This method retrieves the list of packets from the Blacklist table and calculates the duration
            for each packet by subtracting the arrival time from the current time. It then updates the
            duration field in the Blacklist table for each packet.

            Returns:
                None
            """
        logger.info("Update the duration of each packet in the Blacklist table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            now = datetime.now()
            cursor.execute('SELECT id, time_arr FROM Blacklist')
            rows = cursor.fetchall()
            for row in rows:
                packet_id, arrival_time = row
                arrival_datetime = datetime.strptime(arrival_time,
                                                     "%Y-%m-%d %H:%M:%S")
                duration_in_seconds = (now - arrival_datetime).total_seconds()
                cursor.execute(
                    '''
                        UPDATE Blacklist SET duration = ? WHERE id = ?
                    ''', (duration_in_seconds, packet_id))
            conn.commit()
        finally:
            self.release_connection(conn)

    def timeout_remove(self, duration_threshold):
        """
        Delete entries in the Blacklist with a duration greater than the specified threshold.

        Args:
            duration_threshold (int): The threshold duration in seconds.

        Returns:
            None
        """
        logger.info(
            "Delete entries in the Blacklist with a duration greater than %d." %
            (duration_threshold))

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                DELETE FROM Blacklist WHERE CAST(duration AS INTEGER) > ?
            ''', (duration_threshold,))
            conn.commit()
        finally:
            self.release_connection(conn)

    def display(self):
        """
        Display all IPs in the Blacklist.

        Retrieves all rows from the 'Blacklist' table and prints them in a formatted manner.
        The format includes columns for 'id', 'sip', 'dip', 'sport', 'dport', 'protocol',
        'tcp_flag', 'timestamp', 'length', 'time_arr', 'duration', and 'count'.
        """
        logger.info("Display all IPs in the Blacklist")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM Blacklist')
            rows = cursor.fetchall()
            print("Display all IPs in the Blacklist:")
            format_str = "{:<3} {:<15} {:<15} {:<6} {:<6} {:<8} {:<10} {:<20} {:<6} {:<20} {:<8} {:<5}"
            print(
                format_str.format("id", "sip", "dip", "sport", "dport",
                                  "protocol", "tcp_flag", "timestamp", "length",
                                  "time_arr", "duration", "count"))
            for row in rows:
                formatted_row = [
                    str(v) if v is not None else 'None' for v in row
                ]
                print(format_str.format(*formatted_row))
        finally:
            self.release_connection(conn)

    def delete(self, id):
        """
            Delete a record from the Blacklist table based on the given ID.

            Args:
                id (int): The ID of the record to be deleted.

            Returns:
                None

            Raises:
                None
            """
        logger.info("Delete a record from the Blacklist table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                DELETE FROM Blacklist WHERE id = ?
                ''', (id))
            print("Delete successfully!")
        finally:
            self.release_connection(conn)

    def id_reset(self):
        """
            Resets the ID column of the Blacklist table by creating a new table,
            copying the data from the original table, dropping the original table,
            and renaming the new table to Blacklist.

            This method ensures that the ID column starts from 1 and increments
            sequentially for each record in the table.

            Returns:
                None
            """
        logger.info("Reset the ID column of the Blacklist table")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                    CREATE TABLE IF NOT EXISTS Blacklist_new (
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
                    INSERT INTO Blacklist_new (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr, duration, count)
                    SELECT sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr, duration, count FROM Blacklist
                ''')
            cursor.execute('DROP TABLE Blacklist')
            cursor.execute('ALTER TABLE Blacklist_new RENAME TO Blacklist')
            conn.commit()
        except Exception as e:
            logger.error(f"An error occurred: {e}")
        finally:
            self.release_connection(conn)

    def clear(self):
        """
            Clears all data from the tables in the database.

            Raises:
                sqlite3.Error: If an error occurs while clearing the tables.
            """
        logger.info("Clear all data from the tables in the database")
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
            conn.release_connection()

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
        if not os.path.exists(Config.writeinfo_path):
            logger.error(f"The directory does not exist: " +
                         Config.writeinfo_path)
            return

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
                        # parts = row[0].split(',')
                        # sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = parts
                        # sport = int(sport)
                        # dport = int(dport)
                        (sip, dip, sport, dport, protocol, tcp_flag, timestamp,
                         length) = row
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
