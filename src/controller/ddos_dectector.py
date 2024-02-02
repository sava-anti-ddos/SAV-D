import csv
import asyncio
import struct
import glob
from io import StringIO

class SAVAPacketSniffer:

    def __init__(self, ip=None, port=None):
        self.listen_ip = ip
        self.listen_port = port
        asyncio.run(self.main(self.listen_ip, self.listen_port))

    async def handle_client(self, reader, asyncio_writer):
        data_length_bytes = await reader.read(4)
        if not data_length_bytes:
            return

        length = struct.unpack("!I", data_length_bytes)[0]
        data = await reader.read(length)

        message = data.decode('utf-8')
        addr = asyncio_writer.get_extra_info('peername')

        print(f"Received from {addr}: {message}")

        csv_file = StringIO(message)
        csv_reader = csv.reader(csv_file)
        
        with open("sniffer.csv", "a", newline='') as file:
            csv_writer = csv.writer(file)
            for row in csv_reader:
                csv_writer.writerow(row)

        response = f"Received {len(data)} bytes"
        asyncio_writer.write(response.encode())
        await asyncio_writer.drain()

        print("Closing the connection")
        asyncio_writer.close()


    async def main(self, host, port):
        server = await asyncio.start_server(self.handle_client, host, port)
        addr = server.sockets[0].getsockname()
        print(f'Serving on {addr}')

        async with server:
            await server.serve_forever()

