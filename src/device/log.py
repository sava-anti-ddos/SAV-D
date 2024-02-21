import logging
import os


class Log:

    def __init__(self, name):
        self.logger = self.setup_logging(name)

    def setup_logging(self, name):
        log_file = os.path.join('/var/log/', 'savd_device.log')
        logging.basicConfig(
            filename=log_file,
            filemode='a',
            format='[%(asctime)s]-%(levelname)s-%(name)s: %(message)s',
            level=logging.INFO)
        # Assign and return the logger instance to be used by Log instances
        return logging.getLogger(name)


def get_logger(name):
    log_instance = Log(name)
    logger = log_instance.logger
    return logger
