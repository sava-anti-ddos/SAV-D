import sqlite3
from queue import Queue
from threading import Lock
from datetime import datetime
import time
import csv
import os
import shutil
import glob

#BlacklistDatabase中完成对数据库得建立与增删改查，提供连接池解决并发问题
class BlacklistDatabase:
    #__init__用于初始化Blacklist，并确定最大连接数
    #若该路径下没有数据库则建立，若已存在则向该数据库建立多个连接用于后续操作
    def __init__(self, db_name='blacklist.db', max_connections=5):
        self.db_name = db_name
        if not os.path.isfile(self.db_name):
            self.create_table()
        self.pool = Queue(max_connections)
        self.lock = Lock()
        for _ in range(max_connections):
            self.pool.put(self.create_connection())

    #用于与数据库建立连接
    def create_connection(self):
        return sqlite3.connect(self.db_name, check_same_thread=False)

    #从连接池中获取连接，并返回该连接
    def get_connection(self):
        return self.pool.get()

    #释放连接，放回连接池中
    def release_connection(self, conn):
        self.pool.put(conn)

    #在数据库中建立表，表中包括ID、五元组信息与tcp falg、报文时间、系统时间、持续时间、计数器
    #其中系统时间用于计算持续时间、计数器用于记录同一条五元组信息得个数
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
        finally:
            conn.close()
    
    
    #更新blacklist中的表项，用于单条操作
    #如果是第一次出现的五元组信息则直接插入，记录时间
    #如果不是第一次出现的五元组信息则找到该五元组表项后更新count计数与时间信息
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
    
    ##更新blacklist中的表项，用于多条操作
    def blacklist_update_batch(self, data):
        """
        批量更新或插入黑名单数据。
        :param data: 包含多个记录的列表，每个记录是一个字典。
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for row in data:
                sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = (
                    row['sip'], row['dip'], row['sport'], row['dport'], row['protocol'],
                    row['tcp_flag'], row['timestamp'], row['length']
                )
                # 查询现有记录
                cursor.execute('''
                    SELECT id, count FROM Blacklist
                    WHERE sip = ? AND dip = ? AND sport = ? AND dport = ? AND protocol = ?
                ''', (sip, dip, sport, dport, protocol))
                result = cursor.fetchone()
                if result:
                    # 如果存在，更新记录
                    packet_id, count = result
                    cursor.execute('''
                        UPDATE Blacklist SET count = ?, tcp_flag = ?, timestamp = ?, length = ?, time_arr = ? WHERE id = ?
                    ''', (count + 1, tcp_flag, timestamp, length, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), packet_id))
                else:
                    # 如果不存在，插入新记录
                    cursor.execute('''
                        INSERT INTO Blacklist (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        finally:
            self.release_connection(conn)

    #用于更新每条记录在Blacklist中的持续时间，用当前的时间减去表项的记录时间单位为秒
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

    #用于删除Blacklist中超时的表项，超时时间可自定义
    def timeout_remove(self, duration_threshold):
        print("Delete entries in the blacklist with a duration greater than %d."%(duration_threshold))
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM Blacklist WHERE CAST(duration AS INTEGER) > ?
            ''', (duration_threshold,))
            conn.commit()
        finally:
            self.release_connection(conn)

    # def display(self):
    #     conn = self.get_connection()
    #     try:
    #         cursor = conn.cursor()
    #         cursor.execute('SELECT * FROM Blacklist')
    #         rows = cursor.fetchall()
    #         print("display all IPs in the Blacklist:")
    #         for row in rows:
    #             print(row)
    #     finally:
    #         self.release_connection(conn)
            
    def display(self):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM Blacklist')
            rows = cursor.fetchall()
            print("Display all IPs in the Blacklist:")
            # 定义格式化字符串，根据字段内容预估宽度
            format_str = "{:<3} {:<15} {:<15} {:<6} {:<6} {:<8} {:<10} {:<20} {:<6} {:<20} {:<8} {:<5}"
            # 打印列名，对齐表头
            print(format_str.format("id", "sip", "dip", "sport", "dport", "protocol", "tcp_flag", "timestamp", "length", "time_arr", "duration", "count"))
            for row in rows:
                # 使用format_str格式化每行数据
                print(format_str.format(*row))
        finally:
            self.release_connection(conn)




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

    def id_reset(self):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Step 1: 创建一个新表，其结构与原表相同
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
            # Step 2: 将原表数据复制到新表，不包括id列
            cursor.execute('''
                INSERT INTO Blacklist_new (sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr, duration, count)
                SELECT sip, dip, sport, dport, protocol, tcp_flag, timestamp, length, time_arr, duration, count FROM Blacklist
            ''')
            # Step 3: 删除原表
            cursor.execute('DROP TABLE Blacklist')
            # Step 4: 将新表重命名为原表名
            cursor.execute('ALTER TABLE Blacklist_new RENAME TO Blacklist')
            conn.commit()
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.release_connection(conn)

    def clear(self):
        conn=self.get_connection()
        cursor=conn.cursor()
        try:
            # 获取数据库中所有表的名称
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            # 遍历所有表，清空它们的内容
            for table_name in tables:
                print(f"Clearing data from table: {table_name[0]}")
                cursor.execute(f"DELETE FROM {table_name[0]}")
            conn.commit()
            print("All tables cleared successfully.")
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
        finally:
            # 关闭数据库连接
            conn.release_connection()

    #所有链接关闭后断开数据库
    def close(self):
        # 由于使用连接池，关闭连接池中的所有连接
        while not self.pool.empty():
            conn = self.pool.get()
            conn.close()

class CSVHandler:
    def __init__(self, csv_dir, target_dir, encoding='utf-8-sig'):
        self.csv_dir = csv_dir
        self.target_dir = target_dir
        self.encoding = encoding
        # 确保目标目录存在
        if not os.path.exists(self.target_dir):
            print("path error")
            return 

    def csv_read_and_move(self):
        # 搜索源目录下的所有CSV文件
        csv_files = glob.glob(os.path.join(self.csv_dir, '*.csv'))
        data = []
        for file_path in csv_files:
            try:
                with open(file_path, mode='r', encoding=self.encoding) as file:
                    # 每一行只有一个字符串，使用split方法分割字符串
                    reader = csv.reader(file)
                    for row in reader:
                        parts = row[0].split(',')
                        # 根据分割的结果分配数据
                        sip, dip, sport, dport, protocol, tcp_flag, timestamp, length = parts
                        # 转换数据类型
                        sport = int(sport)
                        dport = int(dport)
                        # 将数据存入字典
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
                        data.append(record)
                print(f"读取文件: {file_path}")
                # 这里可以添加处理DataFrame的代码
            except Exception as e:
                print(f"读取CSV文件失败,错误信息: {e}")
            # 移动文件到目标目录
            shutil.move(file_path, os.path.join(self.target_dir, os.path.basename(file_path)))
            print(f"文件已移动到: {os.path.join(self.target_dir, os.path.basename(file_path))}")
        return data


# 测试示例
def test_packet_database():
    # 创建 BlacklistDatabase 实例
    db = BlacklistDatabase('test_blacklist.db', max_connections=10)
    csv_handler = CSVHandler( 'temp/sniffer/','temp/sniffer/','UTF-8-sig')
    db.id_reset()
    ip_data=csv_handler.csv_read_and_move()
    print("插入测试数据...")
    db.blacklist_update_batch(ip_data)

    #查看插入是否成功
    db.display()

    # 为了看到 duration 更新效果，等待几秒
    time.sleep(5)

    # 更新持续时间
    print("更新持续时间...")
    db.duration_update()
    
    #查看时间更新情况
    db.display()

    # 删除持续时间超过特定阈值的记录
    print("删除持续时间超过阈值的记录...")
    db.timeout_remove(300)  # 假设阈值是3秒

    #查看删除情况
    db.display()

    # 关闭数据库连接
    db.close()
    print("测试完成。")

if __name__ == "__main__":
    test_packet_database()