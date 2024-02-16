import logging
import os
from config import Config

log_directory = Config.log_path
log_file = os.path.join(log_directory, 'savd_device.log')
# Set up logging
logging.basicConfig(filename=log_file,
                    filemode='a',
                    format='[%(asctime)s]-%(levelname)s-%(name)s: %(message)s',
                    level=logging.INFO)


def get_logger(name):
    return logging.getLogger(name)
