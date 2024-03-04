import asyncio
import json
import struct
from datetime import datetime
from rule_receive import ReceiveRule
from monitor import PacketInformationUpload
from log import get_logger

logger = get_logger(__name__)


class SAVDProtocol:
    """
    Represents a SAVD protocol message.

    Attributes:
        version (float): The version of the protocol.
        type (str): The type of the message.
        timestamp (float): The timestamp of the message.
        payload (str): The payload of the message.
    """

    def __init__(self, message_type, payload):
        self.version = 0.1
        self.type = message_type
        self.timestamp = datetime.now().timestamp()
        self.payload = payload

    def serialize(self):
        """
        Serializes the SAVDProtocol object into a JSON string.

        Returns:
            str: The serialized JSON string.
        """
        return json.dumps(
            {
                'version': self.version,
                'type': self.type,
                'timestamp': self.timestamp,
                'payload': self.payload
            },
            default=str)

    @staticmethod
    def deserialize(serialized_data):
        """
        Deserializes a JSON string into a SAVDProtocol object.

        Args:
            serialized_data (str): The serialized JSON string.

        Returns:
            SAVDProtocol: The deserialized SAVDProtocol object.

        Raises:
            ValueError: If the serialized data is missing required fields.
        """
        json_data = json.loads(serialized_data)
        if 'type' in json_data and 'payload' in json_data:
            protocol_instance = SAVDProtocol(json_data['type'],
                                             json_data['payload'])
            protocol_instance.timestamp = json_data.get(
                'timestamp',
                datetime.now().timestamp())
            return protocol_instance
        else:
            raise ValueError("Serialized data is missing required fields")


class Transport:
    """
    A class that handles the transport of data to the server.
    """

    def __init__(self, ip=None, port=None, Config=None):
        """
            Initializes a TransportClient object.

            Args:
                ip (str): The IP address of the server. Defaults to None.
                port (int): The port number of the server. Defaults to None.
            """
        self.server_ip = ip
        self.server_port = port

        self.reader = None
        self.reader_lock = asyncio.Lock()
        self.writer = None

        self.connection_ready = asyncio.Event()
        self.connected = False

        if Config is not None:
            self.heartbeat_interval = Config.heartbeat_interval
            self.reconnect_interval = Config.reconnect_interval
        else:
            self.heartbeat_interval = 60
            self.reconnect_interval = 5

        self.Config = Config

    async def connect_to_server(self):
        """
            Connects to the server using the specified IP address and port.

            Raises:
                Exception: If the connection fails.

            Returns:
                None
            """
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.server_ip, self.server_port)
            self.connected = True
            logger.info(
                f"Connected to controller at {self.server_ip}:{self.server_port}"
            )
        except OSError as e:
            self.connected = False
            logger.error(f"Connection failed: {e}. Reconnecting...")
            await asyncio.sleep(self.reconnect_interval)
            return await self.connect_to_server()

        return self.connected

    async def send_heartbeat(self):
        """
            Sends a heartbeat message to the server at regular intervals.

            This method is responsible for sending a heartbeat message to the server
            as long as the client is connected. The heartbeat message helps to keep
            the connection alive and inform the server that the client is still active.

            The method uses the `send_data` method to send the heartbeat message and
            prints a confirmation message after sending the heartbeat.

            The interval between heartbeat messages is determined by the `heartbeat_interval`
            attribute of the transport client.

            """
        while True:
            try:
                await self.send_data(0, "heartbeat")
                logger.info(f"Heartbeat sent.")
            except Exception as e:
                logger.error(f"Failed to send heartbeat: {e}")
            await asyncio.sleep(self.heartbeat_interval)

    @staticmethod
    async def dispatch_message(message):
        """
        Dispatches the received message based on its type.

        Args:
            message: The message to be dispatched.

        Raises:
            Exception: If there is an error while dispatching the message.

        Returns:
            None
        """
        logger.info(f"Dispatching message: {message}")
        try:
            protocol_instance = SAVDProtocol.deserialize(message)
            if protocol_instance.type == 0:
                logger.info("Received heartbeat response")
            elif protocol_instance.type == 1:
                logger.info("Received sniffer data response")
            elif protocol_instance.type == 2:
                logger.info("Received control response")
                rule_receiver = ReceiveRule()
                await rule_receiver.receive_rule(protocol_instance.payload)
            elif protocol_instance.type == 3:
                logger.info(
                    f"Received response message: {protocol_instance.payload}")
        except Exception as e:
            logger.error(f"Failed to dispatch message: {e}")

    async def listen_for_messages(self):
        """
            Listens for incoming messages from the server.

            This method continuously reads data from the reader and decodes it into messages.
            It then dispatches each message for further processing.

            Raises:
                asyncio.IncompleteReadError: If the server closes the connection prematurely.
            """
        logger.info("Listening for messages from the controller.")
        try:
            while True:
                data_length_bytes = await self.reader.readexactly(4)
                data_length = struct.unpack("!I", data_length_bytes)[0]
                data = await self.reader.readexactly(data_length)
                message = data.decode('utf-8')
                logger.info(f"Received message: {message}")
                await self.dispatch_message(message)
        except asyncio.IncompleteReadError:
            logger.error("Controller closed the connection")
            self.connected = False
            self.writer.close()
            await self.writer.wait_closed()
            await self.connect_to_server()

    async def send_data(self, message_type, payload):
        """
            Sends data to the server.

            Args:
                message_type (str): The type of the message.
                payload (str): The payload of the message.

            Returns:
                None
            """
        logger.info(f"Sending data to the controller: {message_type, payload}")
        if not self.connected:
            await self.connect_to_server()
        try:
            protocol_instance = SAVDProtocol(message_type, payload)
            serialized_data = protocol_instance.serialize()
            data_length_bytes = struct.pack(
                "!I", len(serialized_data.encode('utf-8')))
            await self.send(serialized_data, data_length_bytes)
        except Exception as e:
            logger.error(f"Failed to send data: {e}")

    async def send(self, data, data_length_bytes):
        """
            Sends the given data to the server.

            Args:
                data (str): The data to be sent.
                data_length_bytes (bytes): The length of the data in bytes.

            Raises:
                ConnectionError: If the connection is closed and reconnection fails.

            Returns:
                None
            """
        logger.info(f"send data: {data}")
        try:
            if self.writer is not None and not self.writer.is_closing():
                self.writer.write(data_length_bytes)
                await self.writer.drain()

                self.writer.write(data.encode('utf-8'))
                await self.writer.drain()

                logger.info(f"Data sent")
            else:
                logger.info("Connection is closed. Attempting to reconnect...")
                await self.connect_to_server()
        except ConnectionError as e:
            logger.error(f"Failed to send data: {e}")

    async def start(self):
        """
        Starts the transport client by connecting to the server, sending heartbeat,
        and listening for messages.
        """
        logger.info("Starting device transport client")
        await self.connect_to_server()

        await asyncio.sleep(6)
        self.connection_ready.set()

        packet_info_upload = PacketInformationUpload(self.server_ip,
                                                     self.server_port, self,
                                                     self.Config)
        tasks = [
            asyncio.create_task(self.send_heartbeat()),
            asyncio.create_task(self.listen_for_messages()),
            asyncio.create_task(packet_info_upload.periodic_upload())
        ]
        logger.info(
            "Tasks send_heartbeat and listen_for_mesages created. Starting event loop."
        )
        await asyncio.gather(*tasks)
