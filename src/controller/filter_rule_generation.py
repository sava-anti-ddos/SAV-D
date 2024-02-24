from ip_blacklist import Database
from log import get_logger

logger = get_logger(__name__)


#用于生成一个RuleGenerator实例，表明在哪个数据库中操作，需要传入数据库实例
#eg： rulegenerator=Rulegenerator(blacklistdatabase)
# Used to create a RuleGenerator instance, specifying the database in which to operate, and it requires passing a database instance.
# Example: rulegenerator=Rulegenerator(blacklistdatabase)
class RuleGenerator:
    connection = None
    info = None

    def __init__(self, db_name):
        self.db = db_name

    #用于设置需要生成的规则字段组合
    #eg： set_info(info.data)
    # Used to set the rule field combinations that need to be generated.
    # Example: set_info(info.data)
    def set_info(self, information=['ip']):
        self.info = information

    #用于向数据库申请连接
    # Used to request a connection from the database
    def launch(self):
        self.connection = self.db.get_connection()

    #用于向数据库根据规则提取数据，并返回相关数据
    # Used to extract data from the database based on rules and return relevant data
    def fetch_data(self, table_name):
        """
        Fetches specific info from the IPBlacklist table.
        """
        logger.debug("Fetching data from database")
        try:
            cursor = self.connection.cursor()
            query = f"SELECT {', '.join(self.info)} FROM {table_name}"
            cursor.execute(query)
            data = cursor.fetchall()
        finally:
            logger.debug("Data fetched: %s", data)
            return data

    #用于将提取的数据生成规则，最后返回一个rules列表
    # Used to generate rules from the extracted data and return a list of rules
    def generate_rules(self, table_name):
        """
        Generates a list of rules based on the specified info.
        """
        logger.info("Generating rules")
        data = self.fetch_data(table_name)
        rules = []
        for row in data:
            rule = ' '.join(str(item) for item in row)
            rules.append(rule)

        logger.info("Rules generated: %s", rules)
        return rules

    #在rulegenerator完成规则生成后关闭连接
    # Close the connection after rule generation is completed in the RuleGenerator
    def shutdown(self):
        self.conn = None
        self.db.release_connection(self.connection)
        logger.debug("Connection closed")


if __name__ == "__main__":
    db = Database("database.db")
    rg = RuleGenerator(db)
    #从黑名单中生成规则范例
    rg.set_info()
    rg.launch()
    data = rg.generate_rules("IPBlacklist")
    print("blacklist rules extract")
    for row in data:
        print(row)
    rg.shutdown()

    #从库中生成规则范例,目前只支持条件查询
    rg.set_info(['sip', 'dip', 'timestamp', 'tcp_flag'])
    rg.launch()
    data = rg.generate_rules("SnifferInfo")
    print("diy rules")
    for row in data:
        print(row)
    rg.shutdown()
