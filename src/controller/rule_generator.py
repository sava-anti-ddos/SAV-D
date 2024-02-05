from ip_blacklist import DB_Info
from ip_blacklist import BlacklistDatabase


#用于说明需要生成的规则组合，须在初始化时说明
#eg： info=Information(['sip', 'sport', 'dport'] ),其会保存在info.data中
#使用info.data来访问数据格式
# Used to specify the rule combinations that need to be generated, which should be specified during initialization.
# Example: info=Information(['sip', 'sport', 'dport']), and it will be saved in info.data.
# Access the data format using info.data
class Information:
    data=['sip', 'sport', 'dport'] 
    def __init__(self,set_info):
        self.data = set_info

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
    def set_info(self,information):
        self.info = information
    
    #用于向数据库申请连接
    # Used to request a connection from the database
    def launch(self):
        self.connection = self.db.get_connection()
        print("Connection opened")

    #用于向数据库根据规则提取数据，并返回相关数据
    # Used to extract data from the database based on rules and return relevant data
    def fetch_data(self):
        """
        Fetches specific info from the Blacklist table.
        """
        try:
            cursor = self.connection.cursor()
            query = f"SELECT {', '.join(self.info)} FROM Blacklist"
            cursor.execute(query)
            data = cursor.fetchall()
        finally:
            return data

    #用于将提取的数据生成规则，最后返回一个rules列表
    # Used to generate rules from the extracted data and return a list of rules
    def generate_rules(self):
        """
        Generates a list of rules based on the specified info.
        """
        data= self.fetch_data()
        rules = []
        for row in data:
            rule = ' '.join(str(item) for item in row)
            rules.append(rule)
        return rules
    
    #在rulegenerator完成规则生成后关闭连接
    # Close the connection after rule generation is completed in the RuleGenerator
    def shutdown(self):
        self.conn = None
        self.db.release_connection(self.connection)
        print("Connection closed")
        