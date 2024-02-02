class SQLitePool:
    """
    SQLite Helper 提供对 SQLite 数据库的支持
    """

    def __init__(self, path, database, max_connections):
        """
        SQLite Helper 提供一个数据库连接池, 来降低频繁连接数据库造成的时间开销
        """
        self.path = path
        self.database = database
        self.max_connections = max_connections

        self.pool = queue.Queue(maxsize=self.max_connections)
        self.created_connections = 0
        self.timeout = 20

    def create_connections(self):
        """
        创建数据库的连接

        参数:
            None
        返回:
            sqlite3 连接对象
        异常:
            数据连接创建失败
        注意:
            如果存储临时数据库的路径不存在, 会抛出错误和输出到屏幕上
        """

        full_path = os.path.join(self.path, self.database)

        # 检查路径是否存在
        if not os.path.exists(self.path):
            logging.debug(f"数据库的路径不存在:{self.path}")
            print(f"数据库的路径不存在:{self.path}")
            return None
        try:
            connection = sqlite3.connect(full_path)
            return connection
        except sqlite3.Error as error:
            logging.debug(f"数据库连接失败：{error}")
            return None

    def get_connection(self, timeout):
        """
        尝试获取一个数据库连接, 同时实现对数据库连接池的懒加载

        参数:
            timeout(int): 超时设置

        返回:
            sqlite3 连接对象

        异常:
            超时异常, 没有在规定的时间范围内获取到数据库的连接

        注意:
        """
        while True:
            try:
                if self.pool.empty(
                ) and self.created_connections < self.max_connections:
                    # 如果连接池中没有可用的连接, 且已创建的连接数小于最大连接数, 则创建新的连接
                    self.pool.put(self.create_connections())
                    self.created_connections += 1

                return self.pool.get(timeout=timeout)
            except queue.Empty:
                logging.debug("Timeout: No available connections in the pool.")
                print(
                    self.created_connections,
                    "Timeout: No available connections in the pool. Waiting connection..."
                )

    def release_connection(self, connection):
        """
        尝试释放一个数据库连接, 并将其返回到连接池中

        参数:
            connection(sqlite3.Connection): sqlite3 连接对象

        返回:
            None

        异常:

        注意:
        """
        self.pool.put(connection)

    def execute(self, connection, sqls):
        """
        执行多条 sql 语句

        参数:
            sqls(list): sql 语句列表

        返回:
            connection 参数的数据库 cursor

        异常:
            sqlite3 数据执行异常

        注意:
        """
        c = connection.cursor()
        for sql in sqls:
            try:
                c.execute(sql)
            except BaseException as e:
                logging.error("db2:" + repr(e) + sql)
                logging.exception(e)
        return c

    def execute_any(self, sql):
        """
        执行单条 sql 语句

        参数:
            sqls(string): sql 语句

        返回:
            None

        异常:
            sqlite3 数据执行异常

        注意:
        """
        connection = self.get_connection(timeout=self.timeout)
        try:
            c = connection.cursor()
            c.execute(sql)
            connection.commit()
        except Exception as e:
            connection.rollback()
            logging.error(f"Error executing SQL: {e}")
        finally:
            c.close()
            self.release_connection(connection)
