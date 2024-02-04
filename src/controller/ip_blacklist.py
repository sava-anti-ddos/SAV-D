import sqlite3
from queue import Queue
from threading import Lock
from datetime import datetime
import csv
import os
import shutil
import glob

#用于存放数据库文件的路径，实例化时需要传入参数
#eg：  db=DB_Info('blacklist.db')
# Used to specify the path of the database file, a parameter that needs to be passed during instantiation
# Example: db=DB_Info('blacklist.db')
class DB_Info:
    path=""
    def __init__(self,db_path):
        self.path=db_path

#用于存放需要读入的文件夹路径，实例化时需要传入参数
#eg：  read_path=Read_Info('tmp/sniffer/')
# Used to specify the path of the folder that needs to be read, a parameter that needs to be passed during instantiation
# Example: read_path=Read_Info('tmp/sniffer/')
class Read_Info:
    path=""
    def __init__(self,read_path):
        self.path = read_path

#用于存放已读完文件的文件夹路径，实例化时需要传入参数
#eg：  write_path=Read_Info('tmp/sniffer_finish/')
# Used to specify the path of the folder where the read files will be stored, a parameter that needs to be passed during instantiation
# Example: write_path=Read_Info('tmp/sniffer_finish/')
class Write_Info:
    path=""
    def __init__(self,write_path):
        self.path = write_path

#用于说明csv文件的编码类型，实例化时需要传入
#eg:   encodingtype=Encoding('utf-8-sig')
# Used to specify the encoding type of the CSV file, a parameter that needs to be passed during instantiation
# Example: encodingtype=Encoding('utf-8-sig')
class Encoding:
    type=""
    def __init__(self,encodingtype):
        self.type = encodingtype
        
#BlacklistDatabase中完成对数据库得建立与增删改查，提供连接池解决并发问题
#具有唯一性，同一时间只能存在一个实例，在示例化时需要说明可建立连接的最大数目
#eg：blacklistdatabase=BlacklistDatabase(5)
# BlacklistDatabase handles the creation, insertion, deletion, and query of the database, offering a connection pool to solve concurrency issues.
# It is unique, meaning only one instance can exist at a time. When instantiating, it is necessary to specify the maximum number of connections that can be established.
# Example: blacklistdatabase=BlacklistDatabase(5)
class BlacklistDatabase:
    #__init__用于初始化Blacklist，并确定最大连接数
    #若该路径下没有数据库则建立，若已存在则向该数据库建立多个连接用于后续操作
    # __init__ is used to initialize the Blacklist and determine the maximum number of connections.
    # If there is no database at the given path, one is created; if it already exists, multiple connections are established to that database for subsequent operations.
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(BlacklistDatabase, cls).__new__(cls)
        return cls._instance

    def __init__(self, dbname,max_connections=5):
        # 防止__init__方法的重复调用
        # Prevents the __init__ method from being called multiple times
        if not hasattr(self, 'initialized'):  
            self.initialized = True
            self.db_name = dbname
            if not os.path.isfile(self.db_name):
                self.create_table()
            self.pool = Queue(max_connections)
            self.lock = Lock()
            for _ in range(max_connections):
                self.pool.put(self.create_connection())
            print("Blacklist init")

    #用于与数据库建立连接,不向外部提供
    # Used for establishing a connection with the database, not provided to the external
    def create_connection(self):
        return sqlite3.connect(self.db_name, check_same_thread=False)

    #从连接池中获取连接，并返回该连接
    # Retrieves a connection from the connection pool and returns it
    def get_connection(self):
        return self.pool.get()

    #释放连接，放回连接池中
    # Releases the connection, returning it back to the connection pool
    def release_connection(self, conn):
        self.pool.put(conn)

    #在数据库中建立表，表中包括ID、五元组信息与tcp falg、报文时间、系统时间、持续时间、计数器
    #其中系统时间用于计算持续时间、计数器用于记录同一条五元组信息得个数
    # Creates a table in the database, which includes ID, quintuple information and TCP flag, packet time, system time, duration, and counter
    # The system time is used to calculate the duration, and the counter is used to record the number of occurrences of the same quintuple information
    def create_table(self):
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
            print(f"An error occurred while creating the table: {e}")
        finally:
            conn.close()
    
    
    #更新blacklist中的表项，用于单条操作
    #如果是第一次出现的五元组信息则直接插入，记录时间
    #如果不是第一次出现的五元组信息则找到该五元组表项后更新count计数与时间信息
    # Updates entries in the blacklist table for individual operations
    # If it is the first occurrence of a quintuple information, it is directly inserted with the record time
    # If it is not the first occurrence of quintuple information, it finds the quintuple entry and updates the count and time information
    def blacklist_update(self, sip, dip, sport, dport, protocol, tcp_flag,timestamp,length):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, count FROM Blacklist
                WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
            ''', (sip, dip, sport, dport, protocol))
            result = cursor.fetchone()
            if result:
                packet_id, count = result
                cursor.execute('''
                    UPDATE Blacklist SET count = ?, tcp_flag = ?, timestamp=? ,length = ? , time_arr = ? WHERE id = ?
                ''', (count + 1, tcp_flag, timestamp,length,datetime.now().strftime("%Y-%m-%d %H:%M:%S"), packet_id))
            else:
                cursor.execute('''
                    INSERT INTO Blacklist (sip, dip, sport, dport, protocol, tcp_flag, timestamp,length,time_arr)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)
                ''', (sip, dip, sport, dport, protocol, tcp_flag, timestamp,length,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)
    
    #更新blacklist中的表项，用于多条操作
    # Updates entries in the blacklist table for batch operations
    def blacklist_update_batch(self, data):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for row in data:
                sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = (
                    row['sip'], row['dip'], row['sport'], row['dport'], row['protocol'],
                    row['tcp_flag'], row['timestamp'], row['length']
                )
                # 查询现有记录
                # Queries existing records
                cursor.execute('''
                    SELECT id, count FROM Blacklist
                    WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
                ''', (sip, dip, sport, dport, protocol))
                result = cursor.fetchone()
                if result:
                    # 如果存在，更新记录
                    # If exists, update the record
                    packet_id, count = result
                    cursor.execute('''
                        UPDATE Blacklist SET count = ?, tcp_flag = ?, timestamp = ?, length = ?, time_arr = ? WHERE id = ?
                    ''', (count + 1, tcp_flag, timestamp, length, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), packet_id))
                else:
                    # 如果不存在，插入新记录
                    # If not exists, insert a new record
                    cursor.execute('''
                        INSERT INTO Blacklist (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)

    #用于更新每条记录在Blacklist中的持续时间，用当前的时间减去表项的记录时间单位为秒
    # Used to update the duration of each record in Blacklist by subtracting the recorded time from the current time in seconds
    def duration_update(self):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            now = datetime.now()
            cursor.execute('SELECT id, time_arr FROM Blacklist')
            rows = cursor.fetchall()
            for row in rows:
                packet_id, arrival_time = row
                arrival_datetime = datetime.strptime(arrival_time, "%Y-%m-%d %H:%M:%S")
                duration_in_seconds = (now - arrival_datetime).total_seconds()
                cursor.execute('''
                    UPDATE Blacklist SET duration = ? WHERE id = ?
                ''', (duration_in_seconds, packet_id))
            conn.commit()
        finally:
            self.release_connection(conn)

    #用于删除Blacklist中超时的表项，超时时间可自定义，单位秒
    #timeout_remove(5)
    # Used to delete entries in Blacklist that have exceeded the specified timeout duration in seconds
    # Example: timeout_remove(5)

    def timeout_remove(self, duration_threshold):
        print("Delete entries in the Blacklist with a duration greater than %d."%(duration_threshold))
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM Blacklist WHERE CAST(duration AS INTEGER) > ?
            ''', (duration_threshold,))
            conn.commit()
        finally:
            self.release_connection(conn)
    
    #用于展示blacklist表中的所有信息
    # Used to display all information in the blacklist table
    def display(self):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM Blacklist')
            rows = cursor.fetchall()
            print("Display all IPs in the Blacklist:")
            format_str = "{:<3} {:<15} {:<15} {:<6} {:<6} {:<8} {:<10} {:<20} {:<6} {:<20} {:<8} {:<5}"
            print(format_str.format("id", "sip", "dip", "sport", "dport", "protocol", "tcp_flag", "timestamp", "length", "time_arr", "duration", "count"))
            for row in rows:
                formatted_row = [str(v) if v is not None else 'None' for v in row]  
                print(format_str.format(*formatted_row))
        finally:
            self.release_connection(conn)

    #用于删除指定id的信息
    # Used to delete information with a specific ID
    def delete(self,id):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
            DELETE FROM Blacklist WHERE id = ?
            ''',(id)
            )
            print("Delete successfully!")
        finally:
            self.release_connection(conn)

    #由于更新blacklist会导致编号异常，用于对blacklist表中的条目重新排序
    # Used to re-order entries in the blacklist table due to updates that may cause numbering discrepancies
    def id_reset(self):
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
            print(f"An error occurred: {e}")
        finally:
            self.release_connection(conn)

    #用于清空blacklist表中的内容，但不删除该表
    # Used to clear the contents of the blacklist table without deleting the table itself
    def clear(self):
        conn=self.get_connection()
        cursor=conn.cursor()
        try:
            # 获取数据库中所有表的名称
            # Get the names of all tables in the database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            # 遍历所有表，清空它们的内容
            # Iterate through all tables and clear their contents
            for table_name in tables:
                print(f"Clearing data from table: {table_name[0]}")
                cursor.execute(f"DELETE FROM {table_name[0]}")
            conn.commit()
            print("All tables cleared successfully.")
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
        finally:
            # 关闭数据库连接
            # Close the database connection
            conn.release_connection()

    #所有关闭所有连接后断开数据库
    # Close all connections and disconnect from the database
    def close(self):
        # 由于使用连接池，关闭连接池中的所有连接
        # Due to the use of a connection pool, close all connections in the connection pool
        while not self.pool.empty():
            conn = self.pool.get()
            conn.close()

#用于对csv文件的读取等操作，需要明确读的文件夹路径，写的文件夹路径，和编码形式
#eg：csvhandler=CSVHandler(read_path,writhpath,encodingtype)
# Used for operations on CSV files, including reading. It requires specifying the input folder path, output folder path, and encoding type.
# Example: csvhandler=CSVHandler(read_path, write_path, encoding_type)
class CSVHandler:
    def __init__(self,readpath,writepath,encodetype):
        self.csv_dir = readpath
        self.target_dir = writepath
        self.encoding = encodetype
        if not os.path.exists(Write_Info.path):
            print("path error")
            return 

    #读取csv，并把已读的文件根据初始化的路径移动到已读文件夹中，最终返回读取的内容
    def csv_read_and_move(self):
        # 搜索源目录下的所有CSV文件
        # Reads a CSV file and moves the read file to the already-read folder based on the initialized paths. Finally, it returns the read content.
        csv_files = glob.glob(os.path.join(self.csv_dir, '*.csv'))
        data = []
        for file_path in csv_files:
            try:
                with open(file_path, mode='r', encoding=self.encoding) as file:
                    # 每一行只有一个字符串，使用split方法分割字符串
                    # Each line contains a single string, and the split method is used to split the string
                    reader = csv.reader(file)
                    for row in reader:
                        parts = row[0].split(',')
                        # 根据分割的结果分配数据
                        # Assign data based on the split results
                        sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = parts
                        # 转换数据类型
                        # Convert data types
                        sport = int(sport)
                        dport = int(dport)
                        # 将数据存入字典
                        # Store data in a dictionary
                        record = {
                            'sip': sip,
                            'dip': dip,
                            'sport': sport,
                            'dport': dport,
                            'protocol': protocol,
                            'tcp_flag': tcp_flag if tcp_flag != 'None' else None,  # 处理可能的None字符串
                            'timestamp': timestamp,
                            'length': length
                        }
                        # 将字典添加到data列表中
                        # Add the dictionary to the data list
                        data.append(record)
                print(f"Read file: {file_path}")
            except Exception as e:
                print(f"Failed to read the CSV file, error message: {e}")
            # 移动文件到目标目录
            # Move files to the target directory
            shutil.move(file_path, os.path.join(self.target_dir, os.path.basename(file_path)))
            print(f"File has been moved to: {os.path.join(self.target_dir, os.path.basename(file_path))}")
        return data
