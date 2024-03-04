from controller import TransportServer
from config import Config
from rule_issuance import IssueRules
from ip_blacklist import Database
from filter_rule_generation import RuleGenerator

# Create a server instance and all the devices will connect to this
server = TransportServer(Config.controller_ip, Config.controller_port)
issue_rules = IssueRules(server)
db = Database(Config.db_path)
rule_generator = RuleGenerator(db)
