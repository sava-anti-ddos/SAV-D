import configparser
import os

# Get the current directory
current_dir = os.path.dirname(__file__)
config = configparser.ConfigParser()
config.read(os.path.join(current_dir, 'config.ini'))


class Config:

    # Get the controller IP and port from the config file
    controller_ip = config.get('controller', 'controller_ip')
    controller_port = config.get('controller', 'controller_port')
