import asyncio
import struct
import json
from datetime import datetime, timedelta
from config import Config
from ddos_attack_detection import SAVAPacketSniffer
from log import get_logger

logger = get_logger(__name__)


class SAVDProtocol:
    """
    Represents the SAVD protocol for communication between the controller and clients.

    Attributes:
        version (float): The version of the protocol.
        type (int): The type of the protocol message.
        timestamp (float): The timestamp of the protocol message.
        payload (str or list): The payload of the protocol message.

    Methods:
        serialize(): Serializes the protocol instance into a JSON string.
        deserialize(serialized_data): Deserializes the JSON string into a protocol instance.
    """

    def __init__(self, message_type, payload):
        self.version = 0.1
        self.type = message_type
        self.timestamp = datetime.now().timestamp()
        self.payload = payload

    def serialize(self):
        """
        Serializes the protocol instance into a JSON string.

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
        Deserializes the JSON string into a protocol instance.

        Args:
            serialized_data (str): The serialized JSON string.

        Returns:
            SAVDProtocol: The deserialized protocol instance.

        Raises:
            ValueError: If the serialized data is missing required fields.
        """
        data = json.loads(serialized_data)
        if 'type' in data and 'payload' in data:
            protocol_instance = SAVDProtocol(data['type'], data['payload'])
            protocol_instance.timestamp = data.get('timestamp',
                                                   datetime.now().timestamp())
            return protocol_instance
        else:
            raise ValueError("Serialized data is missing required fields")


class TransportServer:
    """
    Represents the transport server for handling client connections and messages.

    Attributes:
        listen_ip (str): The IP address to listen on.
        listen_port (int): The port to listen on.
        trust_clients (dict): A dictionary of trusted clients and their information.
        trust_clients_lock (asyncio.Lock): A lock for synchronizing access to the trust_clients dictionary.
        heartbeat_timeout (timedelta): The timeout duration for client heartbeats.

    Methods:
        cleanup_clients(): Cleans up disconnected clients based on heartbeat timeout.
        send_control_message(payload): Sends a control message to all connected clients.
        handle_client(reader, writer): Handles a client connection and incoming messages.
        dispatch_message(client, server, message): Dispatches a message to the appropriate handler based on the protocol type.
        respones_to_client(client, writer, message): Sends a response message to a client.
        start_server(): Starts the transport server and listens for client connections.
    """

    def __init__(self, ip, port):
        """
            Initializes a TransportServer object.

            Args:
                ip (str): The IP address to listen on.
                port (int): The port number to listen on.

            Attributes:
                listen_ip (str): The IP address to listen on.
                listen_port (int): The port number to listen on.
                trust_clients (dict): A dictionary to store trusted clients.
                trust_clients_lock (asyncio.Lock): A lock to synchronize access to the trust_clients dictionary.
                heartbeat_timeout (timedelta): The timeout duration for heartbeat messages.
            """
        self.listen_ip = ip
        self.listen_port = port
        self.trust_clients = {}
        self.trust_clients_lock = asyncio.Lock()
        self.heartbeat_timeout = timedelta(seconds=300)

    async def cleanup_clients(self):
        """
            Cleans up disconnected clients based on heartbeat timeout.

            This method iterates over the trust_clients dictionary and checks the last heartbeat time of each client.
            If the time difference between the current time and the last heartbeat time is greater than the heartbeat timeout,
            the client is considered disconnected and removed from the trust_clients dictionary.

            Note: This method is intended to be run as a background task using asyncio.
            """
        logger.info("Starting cleanup_clients")
        while True:
            async with self.trust_clients_lock:
                current_time = datetime.now()
                disconnected_clients = []
                for client, client_info in self.trust_clients.items():
                    if current_time - client_info[
                            "last_heartbeat"] > self.heartbeat_timeout:
                        logger.info(f"Client {client} disconnected")
                        disconnected_clients.append(client)
                logger.info(f"Disconnected clients: {disconnected_clients}")
                for client in disconnected_clients:
                    del self.trust_clients[client]
            await asyncio.sleep(self.heartbeat_timeout.total_seconds())

    async def send_control_message(self, payload):
        """
        Sends a control message to all connected clients.

        Args:
            payload (str): The payload of the control message.
        """
        try:
            for client, client_info in self.trust_clients.items():
                writer = client_info["writer"]
                if writer.is_closing():
                    continue
                logger.info(f"Sending control message to {client}")
                await self.respones_to_client(client, writer, payload, 2)
        except Exception as e:
            logger.error(f"Failed to send control message: {e}")

    async def handle_client(self, reader, writer):
        """
        Handles a client connection and incoming messages.

        Args:
            reader (asyncio.StreamReader): The reader object for reading data from the client.
            writer (asyncio.StreamWriter): The writer object for writing data to the client.
        """
        logger.info("New client connected")
        addr = writer.get_extra_info('peername')
        client_ip, client_port = addr[0], addr[1]
        logger.info(f"Client {client_ip}:{client_port} connected")
        client = (client_ip, client_port)
        server = (reader, writer)
        try:
            while True:
                data_length_bytes = await reader.readexactly(4)
                length = struct.unpack("!I", data_length_bytes)[0]
                data = await reader.readexactly(length)
                message = data.decode('utf-8')
                logger.debug(f"Received from {addr}: {message}")
                await self.dispatch_message(client, server, message)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            logger.info(f"Client {client} disconnected")
            writer.close()
            await writer.wait_closed()

    async def dispatch_message(self, client, server, message):
        """
        Dispatches a message to the appropriate handler based on the protocol type.

        Args:
            client (tuple): The client IP and port.
            server (tuple): The reader and writer objects representing the server.
            message (str): The received message.
        """
        logger.info(f"Dispatching message from {client}")
        try:
            protocol_instance = SAVDProtocol.deserialize(message)

            if protocol_instance.type == 0:
                logger.info(f"Received heartbeat from {client}")
                async with self.trust_clients_lock:
                    if client not in self.trust_clients:
                        self.trust_clients[client] = {
                            "last_heartbeat": datetime.now(),
                            "writer": server[1]
                        }
                    else:
                        self.trust_clients[client][
                            "last_heartbeat"] = datetime.now()
                        self.trust_clients[client]["writer"] = server[1]
                logger.info(f"Client {client} added to trust_clients")

                logger.info(f"Sending heartbeat response to {client}")
                await self.respones_to_client(client, server[1],
                                              "heartbeat received", 0)
            elif protocol_instance.type == 1:
                logger.info(f"Received sniffer data from {client}")
                # Ensure payload is a list before passing to sniffer_receive
                if isinstance(protocol_instance.payload, list):
                    (ip, port) = client
                    file_name = f"{ip}_{port}_sniffer_data.csv"
                    logger.info(f"Writing sniffer data to {file_name}")
                    sniffer = SAVAPacketSniffer(file_name)
                    sniffer.sniffer_receive(protocol_instance.payload)
                # Send response to client
                await self.respones_to_client(client, server[1],
                                              "sniffer data received", 1)
            elif protocol_instance.type == 2:
                logger.info(f"Received control message from {client}")
            else:
                logger.warning(f"Unknown message type from {client}")
        except Exception as e:
            logger.error(f"Failed to dispatch message from {client}: {e}")

    async def respones_to_client(self, client, writer, message, message_type=3):
        """
        Sends a response message to a client.

        Args:
            client (tuple): The client IP and port.
            writer (asyncio.StreamWriter): The writer object for writing data to the client.
            message (str): The response message.
        """
        logger.info(f"Sending response message to {client}: {message}")
        try:
            respones = SAVDProtocol(message_type, message).serialize()
            writer.write(struct.pack("!I", len(respones.encode('utf-8'))))
            await writer.drain()
            writer.write(respones.encode('utf-8'))
            await writer.drain()
            logger.info(f"Response message sent to {client}")
        except Exception as e:
            logger.error(f"Failed to send response message to {client}: {e}")

    async def start_server(self):
        """
        Starts the transport server and listens for client connections.
        """
        logger.info(f"Starting server on {self.listen_ip}:{self.listen_port}")

        server = await asyncio.start_server(self.handle_client, self.listen_ip,
                                            self.listen_port)
        addr = server.sockets[0].getsockname()
        logger.info(f"Serving on {addr}")
        asyncio.create_task(self.cleanup_clients())
        async with server:
            await server.serve_forever()


async def transport_server():
    """
    Entry point for starting the transport server.
    """
    server = TransportServer(Config.controller_ip, Config.controller_port)
    await server.start_server()


if __name__ == "__main__":
    asyncio.run(transport_server)
