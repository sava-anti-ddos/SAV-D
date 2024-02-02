
import os
import csv
import queue
import asyncio
import struct
import threading
from config import Config
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
        self.file_cnt = 0

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
        file_path = os.path.join(Config.sniffer_file_path, Config.sniffer_file_name)
        with open(file_path, 'a') as f:
            writer = csv.writer(f)
            while not queue.empty():
                data = queue.get()
                print(f"Writing data to file: {data}")
                writer.writerow(data)

        # make a dir to store the file need to upload
        if not os.path.exists(f"{Config.sniffer_file_path}/upload"):
            os.makedirs(f"{Config.sniffer_file_path}/upload")

        # move the file to the upload dir
        os.rename(
            file_path,
            f"{Config.sniffer_file_path}/upload/{Config.sniffer_file_name}.{self.file_cnt}"
        )

        self.file_cnt += 1


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

        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = None

        self.packet_len = None
        self.flag = None
        self.timestamp = None

    def sniff_interface(self, interface):
        """
        Sniffs packets on the specified network interface.
        """
        sniff(filter="", iface=interface, prn=self.packet_handler)

    def packet_handler(self, packet):
        """
        Handles the captured packet and extracts relevant information.
        """
        if IP in packet:
            self.src_ip = packet[IP].src
            self.dst_ip = packet[IP].dst
            self.packet_len = len(packet)

        if TCP in packet:
            self.protocol = "TCP"
            self.src_port = packet[TCP].sport
            self.dst_port = packet[TCP].dport
            self.flags = packet[TCP].flags
        elif UDP in packet:
            self.protocol = "UDP"
            self.src_port = packet[UDP].sport
            self.dst_port = packet[UDP].dport
        elif ICMP in packet:
            self.protocol = "ICMP"
        elif ARP in packet:
            self.protocol = "ARP"

        self.timestamp = packet.time

        packet_info = [self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol,  self.flag, self.timestamp, self.packet_len]
        
        self.packet_sniffer_queue.add_data(packet_info)

    def start(self):
        """
        Starts sniffing on all available network interfaces.
        """
        threads = []
        for interface in self.interfaces:
            t = threading.Thread(target=self.sniff_interface, args=(interface,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def stop(self):
        """
        Stops sniffing on all available network interfaces.
        """
        print("========== Stopping Sniffing ==========")
        exit()


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

    def format_lines_as_csv(self, lines):
        """Utility function to format lines as CSV data."""
        output = StringIO()
        writer = csv.writer(output)
        for line in lines:
            writer.writerow(line)
        return output.getvalue()

    def upload_packet_information(self, packet_information):
        """
        Uploads the packet information to the specified server.
        """
        asyncio.run(
            Transport(self.upload_server_ip, self.upload_server_port).upload(packet_information))

    def get_data_from_local(self):
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
            BUFFER_SIZE = 1024  # Define the BUFFER_SIZE variable
            with open(f"{file_path}/{file}", "r") as f:
                csv_reader = csv.reader(f)
                lines_buffer = []
                for line in csv_reader:
                    lines_buffer.append(line)
                    if len(lines_buffer) == BUFFER_SIZE:
                        data_to_send = self.format_lines_as_csv(lines_buffer)
                        print(data_to_send)
                        self.upload_packet_information(data_to_send)
                        lines_buffer = []

                if len(lines_buffer) > 0:
                    data_to_send = self.format_lines_as_csv(lines_buffer)
                    self.upload_packet_information(data_to_send)

            os.rename(f"{file_path}/{file}", f"{file_path}/{file}.uploaded")
            os.rename(f"{file_path}/{file}.uploaded",
                      f"{Config.sniffer_file_path}/uploaded/{file}.uploaded")


class Transport:
    """
    A class that handles the transport of data to the server.
    """

    def __init__(self, ip=None, port=None):
        self.server_ip = ip
        self.server_port = port

    async def upload(self, data):
        """
        Uploads the data to the server.
        """
        await self.send_data(data)

    async def send_data(self, data):
        """
        Sends the data to the server and receives a response.
        """
        try:
            reader, writer = await asyncio.open_connection(
                self.server_ip, self.server_port)

            length = struct.pack("!I", len(data))
            writer.write(length)
            await writer.drain()

            # send data
            writer.write(data.encode())
            await writer.drain()

            # wait for response from server
            buffer = await reader.read(128)
            print(f"Received: {buffer.decode()}")

            print("Close the connection")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"An error occurred: {e}")
