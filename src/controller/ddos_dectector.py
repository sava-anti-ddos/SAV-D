import csv


class SAVAPacketSniffer:
    """
    Class representing a packet sniffer for SAVA.

    Attributes:
        None

    Methods:
        __init__: Initializes the SAVAPacketSniffer object.
        sniffer_receive: Writes the sniffer data to a CSV file.
    """

    def __init__(self) -> None:
        pass

    def sniffer_receive(self, sniffer_data):
        """
        Write the sniffer data to a CSV file.

        Args:
            sniffer_data (list): List of rows to be written to the CSV file.
        """
        with open("sniffer.csv", "a", newline='') as file:
            csv_writer = csv.writer(file)
            for row in sniffer_data:
                csv_writer.writerow(row)
