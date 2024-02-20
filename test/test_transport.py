import asyncio
import struct
import json
import csv
import sys
import os
from datetime import datetime, timedelta

script_dir = os.path.dirname(__file__)  # 获取当前脚本的目录
project_root = os.path.join(script_dir, '..')  # 计算项目根目录
sys.path.append(os.path.normpath(project_root))  # 添加到sys.path

from src.device.config import Config


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


class TransportServer:

    def __init__(self, ip, port):
        self.listen_ip = ip
        self.listen_port = port
        self.trust_clients = {}
        self.trust_clients_lock = asyncio.Lock()
        self.heartbeat_timeout = timedelta(seconds=300)

    async def cleanup_clients(self):
        while True:
            async with self.trust_clients_lock:
                current_time = datetime.now()
                disconnected_clients = []
                for client, client_info in self.trust_clients.items():
                    if current_time - client_info[
                            "last_heartbeat"] > self.heartbeat_timeout:
                        print(f"Client {client} timed out")
                        disconnected_clients.append(client)
                for client in disconnected_clients:
                    del self.trust_clients[client]
            await asyncio.sleep(self.heartbeat_timeout.total_seconds())

    async def send_control_message(self, payload):
        try:
            for client, client_info in self.trust_clients.items():
                writer = client_info["writer"]
                if writer.is_closing():
                    continue
                await self.respones_to_client(client, writer, payload)
        except Exception as e:
            print(f"Failed to send control message: {e}")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        client_ip, client_port = addr[0], addr[1]
        client = (client_ip, client_port)
        server = (reader, writer)
        try:
            while True:
                data_length_bytes = await reader.readexactly(4)
                length = struct.unpack("!I", data_length_bytes)[0]
                data = await reader.readexactly(length)
                message = data.decode('utf-8')
                print(f"Received from {addr}: {message}")
                await self.dispatch_message(client, server, message)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            print(f"Client {client} disconnected")
            writer.close()
            await writer.wait_closed()

    async def dispatch_message(self, client, server, message):
        try:
            protocol_instance = SAVDProtocol.deserialize(message)

            if protocol_instance.type == 0:
                print("Received heartbeat")
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

                print(f"Sending heartbeat response to {client}")
                await self.respones_to_client(client, server[1],
                                              "heartbeat received")
            elif protocol_instance.type == 1:
                print("Received sniffer data")
                # Ensure payload is a list before passing to sniffer_receive
                if isinstance(protocol_instance.payload, list):
                    sniffer = SAVAPacketSniffer()
                    sniffer.sniffer_receive(protocol_instance.payload)
                # Send response to client
                await self.respones_to_client(client, server[1],
                                              "sniffer data received")
            elif protocol_instance.type == 2:
                print("Received control message")
            else:
                print("Received unknown message")
        except Exception as e:
            print(f"Error in dispatch_message: {e}")

    async def respones_to_client(self, client, writer, message):
        try:
            respones = SAVDProtocol(3, message).serialize()
            writer.write(struct.pack("!I", len(respones.encode('utf-8'))))
            await writer.drain()
            writer.write(respones.encode('utf-8'))
            await writer.drain()
            print(f"response message sent to {client}")
        except Exception as e:
            print(f"Failed to send response message to {client}: {e}")

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, self.listen_ip,
                                            self.listen_port)
        addr = server.sockets[0].getsockname()
        print(f'Serving on {addr}')
        asyncio.create_task(self.cleanup_clients())
        async with server:
            await server.serve_forever()


class SAVAPacketSniffer:

    def __init__(self) -> None:
        pass

    def sniffer_receive(self, sniffer_data):
        with open("sniffer.csv", "a", newline='') as file:
            csv_writer = csv.writer(file)
            for row in sniffer_data:
                csv_writer.writerow(row)


async def main():
    server = TransportServer(Config.controller_ip, Config.controller_port)
    await server.start_server()


if __name__ == "__main__":
    asyncio.run(main())
