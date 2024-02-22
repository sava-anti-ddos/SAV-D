import configparser
import os
from log import get_logger

current_dir = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(current_dir, "config.ini")

logger = get_logger(__name__)


def initialize_config(config_path):
    """
    Initialize the configuration for the device.
    """
    logger.info("Initializing configuration")
    config_instance = Configuration(config_path)
    logger.info("Configuration initialized: \n%s", config_instance.to_string())
    return config_instance


class Configuration:
    """
    Configuration class for device settings.
    """

    def __init__(self, config_path=config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        self.load_settings()

    def load_settings(self):
        # Get the controller IP and port from the config file
        self.controller_ip = self.config.get('controller', 'controller_ip')
        self.controller_port = self.config.get('controller', 'controller_port')

        # Get the sniffer file path, file name and queue size from the config file
        self.sniffer_file_path = self.config.get('monitor', 'sniffer_file_path')
        self.sniffer_file_name = self.config.get('monitor', 'sniffer_file_name')
        self.sniffer_queue_size = self.config.getint('monitor',
                                                     'sniffer_queue_size')
        self.sniffer_interface_config = self.config.getint(
            'monitor', 'sniffer_interface_config')
        self.sniffer_interface = self.config.get('monitor', 'sniffer_interface')
        self.sniffer_upload_interval = self.config.getint(
            'monitor', 'sniffer_upload_interval')

        # Get the receive rule configuration from the config file
        self.heartbeat_interval = self.config.getint('connection',
                                                     'heartbeat_interval')
        self.reconnect_interval = self.config.getint('connection',
                                                     'reconnect_interval')

        # Get the rule cache
        self.cache_path = self.config.get('rule', 'cache_path')
        self.cache_max_size = self.config.getint('rule', 'cache_max_size')

        # Get log path
        self.log_path = self.config.get('log', 'log_path')

        # Get the is_sava flag
        self.is_sava = self.config.getboolean('sava', 'is_sava')

    def to_string(self):
        string = ""
        string += "controller_ip: " + self.controller_ip + "\n"
        string += "controller_port: " + self.controller_port + "\n"
        string += "sniffer_file_path: " + self.sniffer_file_path + "\n"
        string += "sniffer_file_name: " + self.sniffer_file_name + "\n"
        string += "sniffer_queue_size: " + str(self.sniffer_queue_size) + "\n"
        string += "sniffer_interface_config: " + str(
            self.sniffer_interface_config) + "\n"
        string += "sniffer_interface: " + self.sniffer_interface + "\n"
        string += "sniffer_upload_interval: " + str(
            self.sniffer_upload_interval) + "\n"
        string += "heartbeat_interval: " + str(self.heartbeat_interval) + "\n"
        string += "reconnect_interval: " + str(self.reconnect_interval) + "\n"
        string += "cache_path: " + self.cache_path + "\n"
        string += "cache_max_size: " + str(self.cache_max_size) + "\n"
        string += "log_path: " + self.log_path + "\n"
        string += "is_sava: " + str(self.is_sava)
        return string
