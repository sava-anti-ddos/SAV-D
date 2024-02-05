import asyncio
import json
import struct
from datetime import datetime
from src.device.device_config import Config
from receive_rule import ReceiveRule


class SAVDProtocol:
    version = 0.1

    def __init__(self, type, payload):
        self.type = type
        self.timestamp = datetime.now().timestamp()
        self.payload = payload

    def serialize(self):
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
        data = json.loads(serialized_data)
        if 'type' in data and 'payload' in data:
            protocol_instance = SAVDProtocol(data['type'], data['payload'])
            protocol_instance.timestamp = data.get('timestamp',
                                                   datetime.now().timestamp())
            return protocol_instance
        else:
            raise ValueError("Serialized data is missing required fields")


class Transport:
    """
    A class that handles the transport of data to the server.
    """

    def __init__(self, ip=None, port=None):
        self.server_ip = ip
        self.server_port = port
        self.heartbeat_interval = Config.heartbeat_interval
        self.reconnect_interval = Config.reconnect_interval
        self.reader = None
        self.reader_lock = asyncio.Lock()
        self.writer = None
        self.connected = False

    async def connect_to_server(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.server_ip, self.server_port)
            self.connected = True
            print(f"Connected to server at {self.server_ip}:{self.server_port}")
        except Exception as e:
            self.connected = False
            print(f"Connection failed: {e}. Reconnecting...")
            await asyncio.sleep(self.reconnect_interval)
            await self.connect_to_server()

    async def send_heartbeat(self):
        while True:
            if self.connected:
                await self.send_data(0, "heartbeat")
                print("Heartbeat sent.")
            await asyncio.sleep(self.heartbeat_interval)

    async def dispatch_message(self, message):
        try:
            protocol_instance = SAVDProtocol.deserialize(message)

            if protocol_instance.type == 0:
                print("Received heartbeat")
            elif protocol_instance.type == 1:
                print("Received sniffer data")
            elif protocol_instance.type == 2:
                print("Received control message")
                rule_receiver = ReceiveRule()
                await rule_receiver.receive_rule(protocol_instance.payload)
            elif protocol_instance.type == 3:
                print(f"Received response message: {protocol_instance.payload}")
        except Exception as e:
            print(f"Failed to dispatch message: {e}")

    async def listen_for_messages(self):
        try:
            while True:
                data_length_bytes = await self.reader.readexactly(4)
                data_length = struct.unpack("!I", data_length_bytes)[0]
                data = await self.reader.readexactly(data_length)
                message = data.decode('utf-8')
                print(f"Received message: {message}")
                await self.dispatch_message(message)
        except asyncio.IncompleteReadError:
            print("Server closed the connection.")
            self.connected = False
            self.writer.close()
            await self.writer.wait_closed()
            await self.connect_to_server()

    async def send_data(self, type, payload):
        if not self.connected:
            await self.connect_to_server()
        protocol_instance = SAVDProtocol(type, payload)
        serialized_data = protocol_instance.serialize()
        data_length_bytes = struct.pack("!I",
                                        len(serialized_data.encode('utf-8')))
        await self.send(serialized_data, data_length_bytes)

    async def send(self, data, data_length_bytes):
        if self.writer is not None and not self.writer.is_closing():
            self.writer.write(data_length_bytes)
            await self.writer.drain()
            self.writer.write(data.encode('utf-8'))
            await self.writer.drain()
            print("Data sent to the server.")
        else:
            print("Connection is closed. Attempting to reconnect...")
            await self.connect_to_server()

    async def start(self):
        await self.connect_to_server()
        tasks = [
            asyncio.create_task(self.send_heartbeat()),
            asyncio.create_task(self.listen_for_messages()),
        ]
        await asyncio.gather(*tasks)