import os
import csv
import queue
import threading
import datetime
from src.device.device_config import Config
from src.device.transport_client import Transport
from io import StringIO
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP


class DoubleQueue:
    """
    A class that represents a double-ended queue for storing data.
    """

    def __init__(self):
        self.queue0 = queue.Queue(maxsize=Config.sniffer_queue_size)
        self.queue1 = queue.Queue(maxsize=Config.sniffer_queue_size)
        self.current_queue = 0

    def add_data(self, data):
        """
        Adds data to the current queue and switches queues if the current queue is full.
        """
        current_queue = self.queue0 if self.current_queue == 0 else self.queue1
        current_queue.put(data)

        if current_queue.full():
            self.switch_queue_and_write()

    def switch_queue_and_write(self):
        """
        Switches the current queue and writes the data from the inactive queue to disk.
        """
        inactive_queue = self.queue0 if self.current_queue == 0 else self.queue1
        self.current_queue ^= 1

        self.write_data_to_disk(inactive_queue)

    def write_data_to_disk(self, queue):
        """
        Writes the data from the queue to a file on disk and moves the file to an upload directory.
        """
        # csv file format to store the queue data
        file_path = os.path.join(Config.sniffer_file_path,
                                 Config.sniffer_file_name)
        with open(file_path, 'a') as f:
            writer = csv.writer(f)
            while not queue.empty():
                data = queue.get()
                print(f"Writing data to file: {data}")
                writer.writerow(data)

        # move the file to the upload dir
        self.move_file_to_upload(file_path)

    def move_file_to_upload(self, file_path):
        """
        Moves the file to the upload directory.
        """
        # make a dir to store the file need to upload
        if not os.path.exists(f"{Config.sniffer_file_path}/upload"):
            os.makedirs(f"{Config.sniffer_file_path}/upload")

        # rename the file by time
        now = datetime.datetime.now()
        current_time = now.strftime("%Y-%m-%d_%H-%M-%S")
        # move the file to the upload dir
        os.rename(
            file_path,
            f"{Config.sniffer_file_path}/upload/sniffer-{current_time}.csv")


class PacketSniffer:
    """
    A class that represents a network sniffer.
    """

    def __init__(self, Interface=None):
        self.packet_sniffer_queue = DoubleQueue()
        if Interface is None:
            self.interfaces = get_if_list()
        else:
            self.interfaces = [Interface]

    def sniff_interface(self, interface):
        """
        Sniffs packets on the specified network interface.
        """
        sniff(filter="", iface=interface, prn=self.packet_handler)

    def packet_handler(self, packet):
        """
        Handles the captured packet and extracts relevant information.
        """
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
            flags_str = packet.sprintf("%TCP.flags%")
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        elif ARP in packet:
            protocol = "ARP"

        timestamp = packet.time

        packet_info = [
            src_ip, dst_ip, src_port, dst_port, protocol, flags_str, timestamp,
            packet_len
        ]

        self.packet_sniffer_queue.add_data(packet_info)

    def start(self):
        """
        Starts sniffing on all available network interfaces.
        """
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

    def __init__(self, ip=None, port=None):
        if ip is None and port is None:
            self.upload_server_ip = '127.0.0.1'
            self.upload_server_port = 13145
        else:
            self.upload_server_ip = ip
            self.upload_server_port = port

        self.transport_bus = Transport(self.upload_server_ip,
                                       self.upload_server_port)

    def format_lines_as_csv(self, lines):
        """
        Utility function to format lines as CSV data.
        """
        output = StringIO()
        writer = csv.writer(output)
        for line in lines:
            writer.writerow(line)
        return output.getvalue()

    async def upload_packet_information(self, sniffer_data):
        """
        Uploads the packet information to the specified server.
        """
        await self.transport_bus.send_data(1, sniffer_data)

    async def get_data_from_local(self):
        """
        Retrieves data from the local upload directory and uploads it to the server.
        """
        file_path = os.path.join(Config.sniffer_file_path, 'upload')
        file_list = os.listdir(file_path)
        # make a dir to store the uploaded file
        if not os.path.exists(f"{Config.sniffer_file_path}/uploaded"):
            os.makedirs(f"{Config.sniffer_file_path}/uploaded")

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
                        print(lines_buffer)
                        await self.upload_packet_information(lines_buffer)
                        lines_buffer = []

                if len(lines_buffer) > 0:
                    print(lines_buffer)
                    await self.upload_packet_information(lines_buffer)

            os.rename(f"{file_path}/{file}",
                      f"{Config.sniffer_file_path}/uploaded/{file}")
