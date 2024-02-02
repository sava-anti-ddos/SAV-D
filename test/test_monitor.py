import sys
import asyncio

sys.path.append('src')
from config import Config
from monitor import DoubleQueue, PacketInformationUpload, PacketSniffer, Transport


def test_DoubleQueue():
    """
    Asynchronous test case for the AsyncDoubleQueue class.

    This function tests the functionality of the AsyncDoubleQueue class by performing various test cases.
    """
    # 初始化队列
    queue = DoubleQueue()

    print("\033[92mTest case: add data\033[0m")
    # 异步添加数据
    for i in range(4096):
        queue.add_data(f"Data {i}")

    # 可以在这里添加更多的异步测试逻辑，比如检查队列的状态等

    print("All test cases passed.")


def test_PacketSniffer():
    """
    Test case for PacketSniffer class.

    This function tests the functionality of the PacketSniffer class by performing various test cases.
    """

    # Test case : PacketSniffer
    print("\033[92mTest case 1: PacketSniffer\033[0m")
    sniffer = PacketSniffer('eth0')
    sniffer.start()
    print("start: packet sniffer started")
    sniffer.stop()
    print("stop: packet sniffer stopped")
    print("All test cases passed.")


def test_Transport():
    """
    Test case for Transport class.

    This function tests the functionality of the Transport class by performing various test cases.
    """

    # Test case : Transport
    print("\033[92mTest case : Transport\033[0m")
    asyncio.run(Transport("127.0.0.1", 13145).upload("Test message"))


def test_PacketInformationUpload():
    """
    Test case for PacketInformationUpload class.

    This function tests the functionality of the PacketInformationUpload class by performing various test cases.
    """
    # Test case : PacketInformationUpload
    print("\033[92mTest case : PacketInformationUpload\033[0m")
    packet_info = PacketInformationUpload()
    packet_info.get_data_from_local()
    print("get_data_from_local: get data from /tmp/upload dir")

    print("All test cases passed.")


if __name__ == '__main__':
    print("\033[92m==== Testing monitor.py... ====\033[0m")

    # print("\033[92mTesting AsyncDoubleQueue...\033[0m")
    # test_DoubleQueue()

    # print("\033[92mTesting SAVDRouterUploadInformationWrapper...\033[0m")
    # test_SAVDRouterUploadInformationWrapper()

    # print("\033[92mTesting PacketSniffer...\033[0m")
    # test_PacketSniffer()

    # print("\033[92mTesting Transport...\033[0m")
    # test_Transport()

    # print("\033[92mTesting PacketInformationUpload...\033[0m")
    # test_PacketInformationUpload()

    print("\033[92m==== Done. ====\033[0m")
