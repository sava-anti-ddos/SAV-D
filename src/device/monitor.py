import os
import csv
import queue
import threading
import datetime
import asyncio
from io import StringIO
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP
from log import get_logger

logger = get_logger(__name__)


class DoubleQueue:
    """
    A class that represents a double-ended queue for storing data.
    """

    def __init__(self, Config=None):
        """
        Initializes the Monitor object.

        The Monitor object is responsible for managing two queues, `queue0` and `queue1`,
        which are used for storing data. The `current_queue` variable keeps track of the
        currently active queue.

        Parameters:
            None

        Returns:
            None
        """
        if Config is not None:
            self.queue0 = queue.Queue(maxsize=Config.sniffer_queue_size)
            self.queue1 = queue.Queue(maxsize=Config.sniffer_queue_size)
            self.sniffer_file_path = Config.sniffer_file_path
            self.sniffer_file_name = Config.sniffer_file_name
        else:
            self.queue0 = queue.Queue(maxsize=100)
            self.queue1 = queue.Queue(maxsize=100)
            self.sniffer_file_path = "/tmp"
            self.sniffer_file_name = "sniffer.csv"

        self.current_queue = 0

    def add_data(self, data):
        """
        Adds data to the current queue and switches queues if the current queue is full.

        Parameters:
        - data: The data to be added to the queue.
        """
        logger.debug(f"Adding data to the queue: {data}")
        current_queue = self.queue0 if self.current_queue == 0 else self.queue1
        current_queue.put(data)

        if current_queue.full():
            self.switch_queue_and_write()

    def switch_queue_and_write(self):
        """
        Switches the current queue and writes the data from the inactive queue to disk.
        """
        logger.info("Switching queues and writing data to disk")
        inactive_queue = self.queue0 if self.current_queue == 0 else self.queue1
        self.current_queue ^= 1

        self.write_data_to_disk(inactive_queue)

    def write_data_to_disk(self, queue):
        """
        Writes the data from the queue to a file on disk and moves the file to an upload directory.

        Args:
            queue (Queue): The queue containing the data to be written to the file.

        Returns:
            None
        """
        logger.info("Writing data to disk")
        # csv file format to store the queue data
        logger.info("file path: " + self.sniffer_file_path)
        file_path = os.path.join(self.sniffer_file_path, self.sniffer_file_name)
        with open(file_path, 'a') as f:
            writer = csv.writer(f)
            while not queue.empty():
                data = queue.get()
                logger.debug(f"Writing data to file: {data}")
                writer.writerow(data)

        # move the file to the upload dir
        self.move_file_to_upload(file_path)

    def move_file_to_upload(self, file_path):
        """
        Moves the file to the upload directory.

        Args:
            file_path (str): The path of the file to be moved.

        Returns:
            None
        """
        logger.info("Moving file to upload directory")
        # make a dir to store the file need to upload
        if not os.path.exists(f"{self.sniffer_file_path}/upload"):
            os.makedirs(f"{self.sniffer_file_path}/upload")

        logger.info("Renaming file by time and moving to upload directory")
        # rename the file by time
        now = datetime.datetime.now()
        current_time = now.strftime("%Y-%m-%d_%H-%M-%S")
        # move the file to the upload dir
        logger.info(
            "file rename to: " +
            f"{self.sniffer_file_path}/upload/sniffer-{current_time}.csv")
        os.rename(
            file_path,
            f"{self.sniffer_file_path}/upload/sniffer-{current_time}.csv")

        logger.info("File moved to upload directory")


class PacketSniffer:
    """
    A class that represents a network sniffer.
    """

    def __init__(self, Interface=None, Config=None):
        """
        Initialize the Monitor object.

        Args:
            Interface (str, optional): The network interface to monitor. If None, all available interfaces will be monitored.

        Returns:
            None
        """
        self.interfaces = []
        if Config is not None:
            self.sniffer_file_path = Config.sniffer_file_path
        else:
            self.sniffer_file_path = "/tmp"

        self.packet_sniffer_queue = DoubleQueue(Config)

        if Interface is None:
            self.interfaces = get_if_list()
        else:
            self.interfaces.append(Interface)

        self.init_sniffer_dir()

    def init_sniffer_dir(self):
        """
        Initialize the sniffer directory.

        This method creates the sniffer directory if it does not exist.
        """
        if not os.path.exists(self.sniffer_file_path):
            os.makedirs(self.sniffer_file_path)

        # make a dir to store the file need to upload
        if not os.path.exists(f"{self.sniffer_file_path}/upload"):
            os.makedirs(f"{self.sniffer_file_path}/upload")

        # make a dir to store the file need to upload
        if not os.path.exists(f"{self.sniffer_file_path}/uploaded"):
            os.makedirs(f"{self.sniffer_file_path}/uploaded")

        # check if the dir exists
        logger.info(f"Sniffer file path: {self.sniffer_file_path}")
        logger.info(f"Sniffer upload path: {self.sniffer_file_path}/upload")
        logger.info(f"Sniffer uploaded path: {self.sniffer_file_path}/uploaded")

    def sniff_interface(self, interface):
        """
        Sniffs packets on the specified network interface.

        Args:
            interface (str): The name of the network interface to sniff packets on.

        Returns:
            None
        """
        logger.info(f"Sniffing on interface: {interface}")
        sniff(filter="", iface=interface, prn=self.packet_handler)

    def packet_handler(self, packet):
        """
        Handles the captured packet and extracts relevant information.

        Args:
            packet: The captured packet to be processed.

        Returns:
            None
        """
        logger.debug(f"Handling packet: {packet}")

        src_ip = dst_ip = packet_len = None
        protocol = None
        src_port = dst_port = flags = None
        flags_str = None
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_len = len(packet)

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            # Convert the flags integer to a string representation of the flags list
            # flags_str = packet.sprintf("%TCP.flags%")
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        elif ARP in packet:
            protocol = "ARP"

        timestamp = packet.time

        logger.debug(
            f"Packet info: {src_ip}, {dst_ip}, {src_port}, {dst_port}, {protocol}, {flags}, {timestamp}, {packet_len}"
        )
        packet_info = [
            src_ip, dst_ip, src_port, dst_port, protocol, flags, timestamp,
            packet_len
        ]

        self.packet_sniffer_queue.add_data(packet_info)

    def start(self):
        """
            Starts sniffing on all available network interfaces.

            This method creates a separate thread for each network interface
            and calls the `sniff_interface` method to start sniffing on that interface.
            """
        logger.info(f"Starting packet sniffer on interfaces: " +
                    "".join(self.interfaces))
        threads = []
        for interface in self.interfaces:
            t = threading.Thread(target=self.sniff_interface,
                                 args=(interface,),
                                 daemon=True)
            threads.append(t)
            t.start()


class PacketInformationUpload:
    """
    A class that handles the upload of packet information.
    """

    def __init__(self, ip=None, port=None, transport=None, Config=None):
        """
            Initializes the Monitor object.

            Args:
                ip (str, optional): The IP address of the upload server. Defaults to None.
                port (int, optional): The port number of the upload server. Defaults to None.
            """
        if ip is None and port is None:
            self.upload_server_ip = '127.0.0.1'
            self.upload_server_port = 13145
        else:
            self.upload_server_ip = ip
            self.upload_server_port = port

        if transport is not None:
            self.transport_bus = transport
        else:
            self.transport_bus = Transport(self.upload_server_ip,
                                           self.upload_server_port, Config)

        if Config is not None:
            self.sniffer_file_path = Config.sniffer_file_path
        else:
            self.sniffer_file_path = "/tmp"

        self.Config = Config

    def format_lines_as_csv(self, lines):
        """
            Utility function to format lines as CSV data.

            Args:
                lines (list): A list of lines to be formatted as CSV data.

            Returns:
                str: The formatted CSV data as a string.
            """
        logger.info(f"Formatting lines as CSV: {lines}")
        output = StringIO()
        writer = csv.writer(output)
        for line in lines:
            writer.writerow(line)
        return output.getvalue()

    async def upload_packet_information(self, sniffer_data):
        """
            Uploads the packet information to the specified server.

            Args:
                sniffer_data: The packet information to be uploaded.

            Returns:
                None
            """
        logger.info(f"Uploading packet information: {sniffer_data}")
        await self.transport_bus.send_data(1, sniffer_data)

    async def get_data_from_local(self):
        """
            Retrieves data from the local upload directory and uploads it to the server.

            This method reads files from the local upload directory, processes them in batches,
            and uploads the packet information to the server. The files are then moved to the
            'uploaded' directory.

            Note: This method assumes that the 'upload' and 'uploaded' directories exist in the
            specified file path.

            """
        logger.info("Getting data from local")
        file_path = os.path.join(self.sniffer_file_path, 'upload')
        file_list = os.listdir(file_path)
        logger.info(f"File list: {file_list}")
        # make a dir to store the uploaded file
        if not os.path.exists(f"{self.sniffer_file_path}/uploaded"):
            os.makedirs(f"{self.sniffer_file_path}/uploaded")

        for file in file_list:
            # if file not upload, upload it and rename it with .uploaded
            # then move it to the uploaded dir
            BUFFER_SIZE = 128  # Define the BUFFER_SIZE variable
            with open(f"{file_path}/{file}", "r") as f:
                csv_reader = csv.reader(f)
                lines_buffer = []
                for line in csv_reader:
                    lines_buffer.append(line)
                    if len(lines_buffer) == BUFFER_SIZE:
                        await self.upload_packet_information(lines_buffer)
                        lines_buffer = []

                if len(lines_buffer) > 0:
                    await self.upload_packet_information(lines_buffer)
            logger.info(f"Uploaded file: {file}")
            logger.info(
                f"Fule rename to {self.sniffer_file_path}/uploaded/{file}")
            os.rename(f"{file_path}/{file}",
                      f"{self.sniffer_file_path}/uploaded/{file}")

    async def periodic_upload(self):
        """
        Periodically gets data from local and uploads it using the given PacketInformationUpload instance.

        Args:
            packet_info_upload (PacketInformationUpload): The instance used to upload packet information.

        Returns:
            None
        """
        while True:
            logger.info("Uploading sniffer data to controller")
            await self.get_data_from_local()
            logger.info("Data uploaded to controller")

            logger.info("Sleeping for " +
                        str(self.Config.sniffer_upload_interval) + " seconds")
            await asyncio.sleep(self.Config.sniffer_upload_interval)
