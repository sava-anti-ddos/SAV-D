import csv
import os
from config import Config


class SAVAPacketSniffer:
    """
    Class representing a packet sniffer for SAVA.

    Attributes:
        None

    Methods:
        __init__: Initializes the SAVAPacketSniffer object.
        sniffer_receive: Writes the sniffer data to a CSV file.
    """

    def __init__(self):
        self.sniffer_file_name = Config.name
        self.sinffer_read_path = Config.readinfo_path

    def sniffer_receive(self, sniffer_data):
        """
        Write the sniffer data to a CSV file.

        Args:
            sniffer_data (list): List of rows to be written to the CSV file.
        """
        store_file = os.path.join(self.sinffer_read_path,
                                  self.sniffer_file_name)
        with open(store_file, "a", newline='') as file:
            csv_writer = csv.writer(file)
            for row in sniffer_data:
                csv_writer.writerow(row)


class DDoS:

    def __init__(self) -> None:
        pass
