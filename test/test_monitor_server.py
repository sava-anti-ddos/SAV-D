import csv
import asyncio
import struct
from io import StringIO


async def handle_client(reader, asyncio_writer):
    # 读取表示数据长度的4字节
    data_length_bytes = await reader.read(4)
    if not data_length_bytes:
        return

    # 解析数据长度
    length = struct.unpack("!I", data_length_bytes)[0]
    # 根据解析出的长度读取数据
    data = await reader.read(length)
    # 解码数据
    message = data.decode('utf-8')
    addr = asyncio_writer.get_extra_info('peername')

    print(f"Received from {addr}: {message}")

    # 使用StringIO作为CSV数据的临时存储
    csv_file = StringIO(message)
    # 读取CSV数据
    csv_reader = csv.reader(csv_file)

    # 写入到sniffer.csv文件
    with open("sniffer.csv", "a", newline='') as file:
        csv_writer = csv.writer(file)
        for row in csv_reader:
            csv_writer.writerow(row)

    # 发送响应到客户端
    response = f"Received {len(data)} bytes"
    asyncio_writer.write(response.encode())
    await asyncio_writer.drain()

    print("Closing the connection")
    asyncio_writer.close()


async def main(host, port):
    server = await asyncio.start_server(handle_client, host, port)
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main('127.0.0.1', 13145))
