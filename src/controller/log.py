import logging
import os


class Log:

    def __init__(self, name):
        self.logger = self.setup_logging(name)

    def setup_logging(self, name):
        log_file = os.path.join('/var/log/', 'savd_controller.log')

        debug_log_file = os.path.join('/var/log/', 'savd_controller_debug.log')

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(
            logging.Formatter(
                '[%(asctime)s]-%(levelname)s-%(name)s: %(message)s'))

        debug_file_handler = logging.FileHandler(debug_log_file, mode='a')
        debug_file_handler.setLevel(logging.DEBUG)
        debug_file_handler.setFormatter(
            logging.Formatter(
                '[%(asctime)s]-%(levelname)s-%(name)s: %(message)s'))

        logger.addHandler(file_handler)
        logger.addHandler(debug_file_handler)

        # Assign and return the logger instance to be used by Log instances
        return logger


def get_logger(name):
    log_instance = Log(name)
    logger = log_instance.logger
    return logger
