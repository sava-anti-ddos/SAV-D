import configparser
import os

# Get the current directory
current_dir = os.path.dirname(__file__)
config = configparser.ConfigParser()
config.read(os.path.join(current_dir, 'config.ini'))


class Config:
    """
    A class that represents the configuration settings.

    Attributes:
        controller_ip (str): The IP address of the controller.
        controller_port (str): The port number of the controller.
    """

    # Get the controller IP and port from the config file
    controller_ip = config.get('controller', 'controller_ip')
    controller_port = config.get('controller', 'controller_port')

    db_path = config.get('database', 'db_path')

    name = config.get('sniffer', 'name')
    readinfo_path = config.get('sniffer', 'readinfo_path')
    writeinfo_path = config.get('sniffer', 'writeinfo_path')
    task_time = config.get('sniffer', 'task_time')

    encoding = config.get('sniffer', 'encoding')

    log_path = config.get('log', 'log_path')

    threshold = config.get('ddos', 'threshold')
