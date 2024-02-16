import configparser
import os

# Get the current directory
current_dir = os.path.dirname(__file__)
config = configparser.ConfigParser()
config.read(os.path.join(current_dir, 'config.ini'))


class Config:
    """
    Configuration class for device settings.
    """

    # Get the controller IP and port from the config file
    controller_ip = config.get('controller', 'controller_ip')
    controller_port = config.get('controller', 'controller_port')

    # Get the sniffer file path, file name and queue size from the config file
    sniffer_file_path = config.get('monitor', 'sniffer_file_path')
    sniffer_file_name = config.get('monitor', 'sniffer_file_name')
    sniffer_queue_size = config.getint('monitor', 'sniffer_queue_size')
    sniffer_interface = config.get('monitor', 'sniffer_interface')
    sniffer_upload_interval = config.getint('monitor',
                                            'sniffer_upload_interval')

    # Get the receive rule configuration from the config file
    heartbeat_interval = config.getint('connection', 'heartbeat_interval')
    reconnect_interval = config.getint('connection', 'reconnect_interval')

    # Get the rule cache
    cache_path = config.get('rule', 'cache_path')
    cache_max_size = config.getint('rule', 'cache_max_size')

    # Get log path
    log_path = config.get('log', 'log_path')