import csv
import os
import time
from config import Config
from log import get_logger
from rule_issuance import IssueRules

logger = get_logger(__name__)


class SAVAPacketSniffer:
    """
    Class representing a packet sniffer for SAVA.

    Attributes:
        None

    Methods:
        __init__: Initializes the SAVAPacketSniffer object.
        sniffer_receive: Writes the sniffer data to a CSV file.
    """

    def __init__(self, name=None):
        if name is None:
            self.sniffer_file_name = "sniffer_data.csv"
        else:
            self.sniffer_file_name = name
        self.sinffer_read_path = Config.readinfo_path

    def sniffer_receive(self, sniffer_data):
        """
        Write the sniffer data to a CSV file.

        Args:
            sniffer_data (list): List of rows to be written to the CSV file.
        """
        logger.info("Writing sniffer data to file")
        store_file = os.path.join(self.sinffer_read_path,
                                  self.sniffer_file_name)
        with open(store_file, "a", newline='') as file:
            csv_writer = csv.writer(file)
            for row in sniffer_data:
                csv_writer.writerow(row)

        logger.info(f"Store to file: " + store_file)


class DDoS:

    def __init__(self):
        self.baseline = {}
        self.count_array = {}
        self.threshold = Config.threshold
        self.rule_issuance = IssueRules()

    async def detect_ddos(self, data):
        """
        Detects a DDoS attack.

        Args:
            data (list): The data to be analyzed.

        Returns:
            bool: True if a DDoS attack is detected, False otherwise.
        """
        logger.info("Detecting DDoS attack from datas")
        for row in data:
            (sip, dip, sport, dport, protocol, flags, timestamp, length) = row
            # Check if the packet is part of a DDoS attack
            self.count_array[timestamp] += 1
            for key in self.count_array:
                self.baseline[(sip, dip)] += self.count_array[key]
                if timestamp - key > 60:
                    self.baseline[(sip, dip)] -= self.count_array[key]
                    self.count_array.pop(key)

            if self.baseline[(sip, dip)] > self.threshold:
                logger.info(f"DDoS attack detected from {sip} to {dip}")
                self.rule_issuance.send_rules([sip, dip])
                return True
        return False
