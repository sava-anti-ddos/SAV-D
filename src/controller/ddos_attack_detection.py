import csv
import os
from config import Config
from log import get_logger
from ip_blacklist import Database

logger = get_logger(__name__)
db = Database(Config.db_path)


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
        self.ddos = DDoS()

    def sniffer_receive(self, sniffer_data):
        """
        Write the sniffer data to a CSV file.

        Args:
            sniffer_data (list): List of rows to be written to the CSV file.
        """
        self.ddos.detect_ddos(sniffer_data)

        logger.info("sniffer_receive function: Writing data to file")
        store_file = os.path.join(self.sinffer_read_path,
                                  self.sniffer_file_name)
        with open(store_file, "a", newline='') as file:
            csv_writer = csv.writer(file)
            for row in sniffer_data:
                csv_writer.writerow(row)

        logger.info(f"Store to file: " + store_file)

        self.ddos.detect_ddos(sniffer_data)


class DDoS:

    def __init__(self):
        self.baseline = {}
        self.count_array = {}
        self.window_left = 0.0
        self.window_right = 0.0
        self.window_interval = 0.0
        self.threshold = Config.threshold

    def detect_ddos(self, data):
        """
        Detects a DDoS attack.

        Args:
            data (list): The data to be analyzed.

        Returns:
            bool: True if a DDoS attack is detected, False otherwise.
        """
        logger.info("Detecting DDoS attack from datas")
        try:
            for row in data:
                (sip, dip, sport, dport, protocol, flags, packet_timestamp,
                 length) = row

                timestamp = float(packet_timestamp)

                if self.window_left == 0:
                    self.window_left = timestamp

                if timestamp > self.window_right:
                    self.window_right = timestamp

                if not sip or not dip:
                    continue
                # Check if the packet is part of a DDoS attack
                if (sip, dip, timestamp) not in self.count_array.keys():
                    self.count_array[(sip, dip, timestamp)] = 0
                self.count_array[(sip, dip, timestamp)] += 1

            logger.debug(f"Count array: {self.count_array}")

            for key in list(self.count_array.keys()):
                (sip, dip, t) = key
                # clean up the count array
                if t < self.window_left:
                    del self.count_array[key]
                    continue
                if (sip, dip) not in self.baseline:
                    self.baseline[(sip, dip)] = 0

                self.baseline[(sip, dip)] += self.count_array[key]

            for key in self.baseline.keys():
                if self.baseline[key] > self.threshold:
                    logger.info(f"DDoS attack detected from {sip} to {dip}")
                    logger.info(f"insert {dip} to blacklist")
                    db.ip_blacklist_update(dip)

            # reset the window
            self.window_interval = self.window_right - self.window_left
            self.window_left = self.window_right
            # reset the baseline
            self.baseline = {}
        except Exception as e:
            logger.error(f"Error in detect_ddos: {e}")
